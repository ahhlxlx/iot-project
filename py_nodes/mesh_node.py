"""
py_nodes/mesh_node/mesh_node.py
Mesh Node for Maker Pi Pico W
Runs WiFi + BLE + LoRa simultaneously.
- Broadcasts Hello on all 3 protocols to discover neighbours
- Sends data packets using best protocol from routing table
- Listens for incoming packets on all 3 protocols
- Forwards packets toward gateway using cost function
- Same file flashed on every Pico W, just change NODE_ID

Wiring for LoRa SPI module (SX1276/RFM95):
  LoRa SCK  → GP18
  LoRa MOSI → GP19
  LoRa MISO → GP16
  LoRa CS   → GP17
  LoRa RST  → GP14
  LoRa IRQ  → GP15

Fixes applied:
  - BLE IRQ handler no longer calls ble.gap_advertise() directly (caused OSError ENODEV crash)
  - Re-advertising after disconnect is now handled safely in the main loop via a flag
  - ble_irq wrapped in top-level try/except to prevent IRQ crash from killing BLE stack
"""

import network
import socket
import time
import json
import _thread
import utime
import sys
import bluetooth
from machine import Pin, SPI

sys.path.append('/CommonNodeCode')
from metrics import Metrics
from packet_format import Packet
from routing_table import RoutingTable
from config import WIFI_SSID, WIFI_PASSWORD, GATEWAY_IP   # credentials on device only

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← change NODE_ID per device before flashing
# ─────────────────────────────────────────────────────────────────────────────
NODE_ID          = 0x04        # 0x01 = Node A, 0x02 = Node B, 0x03 = Node C, 0x04 = Node D
GATEWAY_ID       = 0xFF        # Reserved for gateway

PROTOCOL_WIFI    = 2
PROTOCOL_BLE     = 1
PROTOCOL_LORA    = 3

# WiFi
BROADCAST_IP     = "255.255.255.255"
UDP_PORT         = 5005

# Timing
HELLO_INTERVAL   = 5      # seconds between Hello broadcasts
PACKET_INTERVAL  = 2      # seconds between data transmissions
MAX_SEQ          = 65535

# BLE
BLE_NAME         = f"MeshNode_{NODE_ID:#04x}"
_MESH_SVC_UUID   = bluetooth.UUID(0xFEAA)
_MESH_CHAR_UUID  = bluetooth.UUID(0x2A56)

# LoRa SPI pins (SX1276/RFM95)
LORA_SCK         = 18
LORA_MOSI        = 19
LORA_MISO        = 16
LORA_CS          = 17
LORA_RST         = 14
LORA_DIO0        = 15
LORA_FREQ        = 923      # MHz — 915-928 MHz for SG/AU region
# ─────────────────────────────────────────────────────────────────────────────


# ── Shared state (all threads share these) ───────────────────────────────────
metrics         = Metrics()
routing_table   = RoutingTable()
seq_num         = 0
seq_lock        = _thread.allocate_lock()

# Track neighbour IPs for WiFi forwarding: {node_id: ip_string}
neighbour_ips   = {}
neighbour_lock  = _thread.allocate_lock()
my_ip           = None   # set in main() after WiFi connects, read by send_data()
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def next_seq():
    global seq_num
    with seq_lock:
        seq_num = (seq_num + 1) % MAX_SEQ
        return seq_num


def build_hello_payload(protocol, extra=None):
    """JSON Hello message for any protocol."""
    msg = {
        "type"     : "HELLO",
        "node_id"  : NODE_ID,
        "protocol" : protocol,
        "timestamp": utime.ticks_ms(),
    }
    if extra:
        msg.update(extra)
    return json.dumps(msg)


def build_data_payload(pkt: Packet):
    """JSON Data message."""
    return json.dumps({
        "type"        : "DATA",
        "src_id"      : pkt.src_id,
        "dest_id"     : pkt.dest_id,
        "seq_num"     : pkt.seq_num,
        "protocol"    : pkt.protocol,
        "hop_count"   : pkt.hop_count,
        "path"        : pkt.path,
        "send_time_ms": pkt.send_time_ms,
        "rssi"        : 0,
    })


def make_packet(dest, protocol):
    """Create and record a new outgoing packet."""
    seq = next_seq()
    pkt = Packet(src_id=NODE_ID, dest_id=dest,
                 seq_num=seq, protocol=protocol)
    pkt.hop_count    = 1
    pkt.path         = [NODE_ID]
    pkt.send_time_ms = utime.ticks_ms()
    metrics.record_send(seq)
    return pkt


def handle_received_data(msg, sender_label="?"):
    """
    Common handler for DATA packets received on ANY protocol.
    - Loop detection: drop packet if NODE_ID already in path
    - If dest is GATEWAY_ID: forward toward gateway
    - If dest is NODE_ID: record metrics
    - Otherwise: forward via best hop
    """
    dest = msg.get("dest_id")
    seq  = msg.get("seq_num", -1)
    path = msg.get("path", [])

    # Drop packet if we are already in the path — prevents forwarding loops
    if NODE_ID in path:
        print(f"[Route] Loop detected — dropping seq={seq}")
        return

    if dest == GATEWAY_ID:
        # Packet is heading to gateway — forward it along
        forward_packet(msg)
        return

    if dest == NODE_ID:
        recv    = utime.ticks_ms()
        latency = utime.ticks_diff(recv, msg.get("send_time_ms", recv))
        metrics.record_receive(seq, recv)
        src = msg.get("src_id")
        if src in routing_table.entries:
            entry = routing_table.entries[src]
            routing_table.update_route(
                neighbor_id = src,
                avg_latency = metrics.calculate_average_latency(),
                rssi        = msg.get("rssi", 0),
                power_cost  = entry.power_cost,
                protocol    = entry.protocol,
            )
        print(f"[DATA] For us  seq={seq}  latency={latency}ms  from={sender_label}")
    else:
        forward_packet(msg)


def send_data():
    """
    Send data toward the gateway via the best next hop.
    Final dest is always GATEWAY_ID, but the packet is physically
    sent to the best neighbour who then forwards it onward — enabling
    true multi-hop mesh routing.

    Routing sequence:
      1. select_best_next_hop() picks lowest-cost neighbour
      2. Packet dest_id = GATEWAY_ID (final destination)
      3. Packet is SENT to the next hop node's IP/handle
      4. That node receives it, sees dest_id != NODE_ID, calls forward_packet()
      5. Repeats until gateway receives it (hops > 1 in gateway log)
    """
    best_hop = routing_table.select_best_next_hop()

    # No known neighbours yet — flood all protocols to bootstrap discovery.
    # Once we receive an ACK, the gateway gets registered and we switch to
    # single-protocol targeted sends.
    if best_hop is None or best_hop == 0xFF:
        print("[Node] No known neighbours — flooding all protocols")
        if my_ip:
            wifi_send_to_gateway()
        ble_send_to_gateway()
        lora_send_to_gateway()
        return

    entry    = routing_table.entries.get(best_hop)
    protocol = entry.protocol if entry else PROTOCOL_WIFI

    # Build packet — final destination is always the gateway
    pkt     = make_packet(GATEWAY_ID, protocol)
    payload = build_data_payload(pkt)

    if protocol == PROTOCOL_WIFI and wifi_sock:
        with neighbour_lock:
            hop_ip = neighbour_ips.get(best_hop, GATEWAY_IP)
        try:
            wifi_sock.sendto(payload.encode(), (hop_ip, UDP_PORT))
            print(f"[WiFi] Data seq={pkt.seq_num} → {best_hop:#04x} (next hop)")
        except OSError as e:
            print(f"[WiFi] Send error: {e}")

    elif protocol == PROTOCOL_BLE:
        if not _ble_connections:
            print("[BLE] No BLE connections — skipping")
            return
        data = payload.encode()[:512]
        for conn_handle in list(_ble_connections.keys()):
            try:
                ble.gatts_notify(conn_handle, _ble_char_handle, data)
                print(f"[BLE] Data seq={pkt.seq_num} → {best_hop:#04x} (next hop)")
            except Exception as e:
                print(f"[BLE] Notify error: {e}")
                _ble_connections.pop(conn_handle, None)

    elif protocol == PROTOCOL_LORA:
        lora_send(payload)
        print(f"[LoRa] Data seq={pkt.seq_num} → {best_hop:#04x} (next hop)")


def forward_packet(msg: dict):
    """
    Forward a packet toward the gateway via the best next hop.
    Skips any node already in the packet path to prevent loops.
    """
    path = msg.get("path", [])

    # Pick best hop, skipping nodes already visited
    candidates = {k: v for k, v in routing_table.entries.items() if k not in path}
    if not candidates:
        print(f"[Route] No valid next hop (all candidates in path) — dropping seq={msg.get('seq_num')}")
        return

    # Find lowest cost candidate
    best_hop = min(
        candidates,
        key=lambda nid: candidates[nid].avg_latency + (candidates[nid].power_cost * 10)
    )

    msg["hop_count"] = msg.get("hop_count", 0) + 1
    msg["path"]      = path + [NODE_ID]
    payload          = json.dumps(msg)

    entry    = routing_table.entries.get(best_hop)
    protocol = entry.protocol if entry else PROTOCOL_WIFI

    if protocol == PROTOCOL_WIFI:
        with neighbour_lock:
            hop_ip = neighbour_ips.get(best_hop, GATEWAY_IP)
        if hop_ip and wifi_sock:
            try:
                wifi_sock.sendto(payload.encode(), (hop_ip, UDP_PORT))
                print(f"[Route] WiFi forward seq={msg.get('seq_num')} → {best_hop:#04x} ({hop_ip})")
            except OSError as e:
                print(f"[Route] WiFi forward error: {e}")

    elif protocol == PROTOCOL_LORA:
        lora_send(payload)
        print(f"[Route] LoRa forward seq={msg.get('seq_num')} → {best_hop:#04x}")

    elif protocol == PROTOCOL_BLE:
        ble_send(payload, best_hop)
        print(f"[Route] BLE forward seq={msg.get('seq_num')} → {best_hop:#04x}")


# ══════════════════════════════════════════════════════════════════════════════
# WIFI
# ══════════════════════════════════════════════════════════════════════════════

wifi_sock = None


def wifi_connect():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(WIFI_SSID, WIFI_PASSWORD)
    print(f"[WiFi] Connecting to {WIFI_SSID}", end="")
    timeout = 15
    while not wlan.isconnected() and timeout > 0:
        print(".", end="")
        time.sleep(1)
        timeout -= 1
    if not wlan.isconnected():
        print("\n[WiFi] Failed — continuing without WiFi")
        return None, None
    ip = wlan.ifconfig()[0]
    print(f"\n[WiFi] Connected  IP={ip}")
    return wlan, ip


def wifi_setup(my_ip):
    global wifi_sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    sock.settimeout(0.3)
    wifi_sock = sock
    return sock


def wifi_broadcast_hello(my_ip):
    if not wifi_sock:
        return
    msg = build_hello_payload(PROTOCOL_WIFI, {"ip": my_ip})
    try:
        wifi_sock.sendto(msg.encode(), (BROADCAST_IP, UDP_PORT))
        print(f"[WiFi] Hello broadcast from {NODE_ID:#04x}")
    except OSError as e:
        print(f"[WiFi] Hello error: {e}")


def wifi_send_to_gateway():
    if not wifi_sock:
        return
    pkt     = make_packet(GATEWAY_ID, PROTOCOL_WIFI)
    payload = build_data_payload(pkt)
    try:
        wifi_sock.sendto(payload.encode(), (GATEWAY_IP, UDP_PORT))
        print(f"[WiFi] Data seq={pkt.seq_num} → Gateway")
    except OSError as e:
        print(f"[WiFi] Send error: {e}")


def wifi_listener():
    """Runs on second core — listens for WiFi UDP packets."""
    while True:
        if not wifi_sock:
            time.sleep(1)
            continue
        try:
            data, addr = wifi_sock.recvfrom(512)
            sender_ip  = addr[0]
            msg        = json.loads(data.decode())

            if msg["type"] == "HELLO":
                nid = msg.get("node_id")
                if nid is None:
                    continue
                with neighbour_lock:
                    neighbour_ips[nid] = msg.get("ip", sender_ip)
                # Register neighbour in routing table regardless of whether
                # it is another mesh node or the gateway
                routing_table.update_route(nid, 0, msg.get("rssi", 0), 1.0, PROTOCOL_WIFI)
                print(f"[WiFi] Hello from {nid:#04x}  ip={sender_ip}")

            elif msg["type"] == "DATA":
                handle_received_data(msg, sender_ip)

            elif msg["type"] == "ACK":
                sent    = msg.get("send_time_ms", 0)
                latency = utime.ticks_diff(utime.ticks_ms(), sent)
                if latency < 0 or latency > 60_000:
                    latency = 0
                seq     = msg.get("seq_num", -1)
                src_id  = msg.get("dest_id", GATEWAY_ID)  # ACK dest_id is our node id
                metrics.record_receive(seq)
                # FIX: register the gateway as a reachable neighbour via WiFi
                # so select_best_next_hop() returns GATEWAY_ID instead of 0xFF
                routing_table.update_route(GATEWAY_ID, latency, 0, 1.0, PROTOCOL_WIFI)
                with neighbour_lock:
                    neighbour_ips[GATEWAY_ID] = sender_ip
                print(f"[WiFi] ACK seq={seq}  latency={latency}ms")

        except OSError:
            pass
        except Exception as e:
            print(f"[WiFi] Listener error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# BLE
# ══════════════════════════════════════════════════════════════════════════════

ble             = bluetooth.BLE()
ble_enabled     = False
_ble_connections    = {}
_ble_char_handle    = None
_ble_reconnect_needed = False   # FIX: flag set in IRQ, acted on in main loop


def _ble_build_adv_data():
    return (bytearray(b'\x02\x01\x06') +
            bytearray([len(BLE_NAME) + 1, 0x09]) +
            BLE_NAME.encode())


def ble_setup():
    global ble_enabled, _ble_char_handle
    try:
        ble.active(True)
        ble.config(gap_name=BLE_NAME)
        ble.irq(ble_irq)

        _FLAG_READ   = 0x0002
        _FLAG_WRITE  = 0x0008
        _FLAG_NOTIFY = 0x0010
        services = (
            (bluetooth.UUID(0xFEAA), (
                (bluetooth.UUID(0x2A56), _FLAG_READ | _FLAG_WRITE | _FLAG_NOTIFY),
            )),
        )
        ((handle,),) = ble.gatts_register_services(services)
        _ble_char_handle = handle  # FIX: assign to global, not local variable

        ble.gap_advertise(100_000, _ble_build_adv_data())

        ble_enabled = True
        print(f"[BLE] Advertising as '{BLE_NAME}'")

    except Exception as e:
        print(f"[BLE] Setup failed: {e}")


def ble_irq(event, data):
    """
    BLE interrupt handler.
    FIX: Never call ble.*() from inside this callback — it crashes the BLE
    stack on MicroPython (OSError ENODEV). Only read data and set flags here.
    Re-advertising is handled safely in the main loop.
    """
    global _ble_reconnect_needed

    _IRQ_CENTRAL_CONNECT    = 1
    _IRQ_CENTRAL_DISCONNECT = 2
    _IRQ_GATTS_WRITE        = 3

    try:
        if event == _IRQ_CENTRAL_CONNECT:
            conn_handle, _, _ = data
            _ble_connections[conn_handle] = True
            print(f"[BLE] Connected handle={conn_handle}")

        elif event == _IRQ_CENTRAL_DISCONNECT:
            conn_handle, _, _ = data
            _ble_connections.pop(conn_handle, None)
            _ble_reconnect_needed = True  # FIX: flag only — no ble calls here
            print(f"[BLE] Disconnected handle={conn_handle} — will re-advertise")

        elif event == _IRQ_GATTS_WRITE:
            conn_handle, value_handle = data
            raw = ble.gatts_read(value_handle)
            try:
                msg = json.loads(raw.decode())
                if msg.get("type") == "HELLO":
                    nid = msg["node_id"]
                    routing_table.update_route(nid, 0, 0, 0.5, PROTOCOL_BLE)
                    print(f"[BLE] Hello from {nid:#04x}")
                elif msg.get("type") == "DATA":
                    handle_received_data(msg, f"BLE:{conn_handle}")
            except Exception as e:
                print(f"[BLE] IRQ parse error: {e}")

    except Exception as e:
        # Catch-all so a crash here never kills the BLE stack
        print(f"[BLE] IRQ error event={event}: {e}")


def ble_broadcast_hello():
    """Notify all connected BLE centrals with a Hello packet."""
    if not ble_enabled or not _ble_char_handle:
        return
    payload = build_hello_payload(PROTOCOL_BLE).encode()
    for conn_handle in list(_ble_connections.keys()):
        try:
            ble.gatts_notify(conn_handle, _ble_char_handle, payload)
        except Exception as e:
            print(f"[BLE] Hello notify error: {e}")
    print(f"[BLE] Hello sent to {len(_ble_connections)} peer(s)")


def ble_send(payload: str, target_node_id: int):
    """Notify all connected BLE peers."""
    if not ble_enabled or not _ble_char_handle:
        return
    data = payload.encode()[:512]
    for conn_handle in list(_ble_connections.keys()):
        try:
            ble.gatts_notify(conn_handle, _ble_char_handle, data)
        except Exception as e:
            print(f"[BLE] Send error: {e}")


def ble_send_to_gateway():
    """Send a data packet to gateway via BLE notification."""
    if not ble_enabled or not _ble_char_handle:
        return
    if not _ble_connections:
        print("[BLE] No BLE connections — skipping BLE send")
        return
    pkt     = make_packet(GATEWAY_ID, PROTOCOL_BLE)
    payload = build_data_payload(pkt).encode()[:512]
    for conn_handle in list(_ble_connections.keys()):
        try:
            ble.gatts_notify(conn_handle, _ble_char_handle, payload)
            print(f"[BLE] Data seq={pkt.seq_num} → Gateway (handle={conn_handle})")
        except Exception as e:
            print(f"[BLE] Notify error: {e}")
            _ble_connections.pop(conn_handle, None)


# ══════════════════════════════════════════════════════════════════════════════
# LORA (SX1276 via SPI)
# ══════════════════════════════════════════════════════════════════════════════

_REG_FIFO          = 0x00
_REG_OP_MODE       = 0x01
_REG_FR_MSB        = 0x06
_REG_FR_MID        = 0x07
_REG_FR_LSB        = 0x08
_REG_PA_CONFIG     = 0x09
_REG_FIFO_ADDR_PTR = 0x0D
_REG_FIFO_TX_BASE  = 0x0E
_REG_FIFO_RX_BASE  = 0x0F
_REG_FIFO_RX_CURR  = 0x10
_REG_IRQ_FLAGS     = 0x12
_REG_RX_NB_BYTES   = 0x13
_REG_PKT_RSSI      = 0x1A
_REG_PAYLOAD_LEN   = 0x22
_REG_MODEM_CONFIG1 = 0x1D
_REG_MODEM_CONFIG2 = 0x1E
_REG_SYNC_WORD     = 0x39
_REG_DIO_MAPPING1  = 0x40
_REG_VERSION       = 0x42

_MODE_SLEEP      = 0x00
_MODE_STDBY      = 0x01
_MODE_TX         = 0x03
_MODE_RXCONT     = 0x05
_MODE_LONG_RANGE = 0x80

lora_spi = None
lora_cs  = None
lora_rst = None
lora_ok  = False


def _lora_write(reg, val):
    lora_cs.value(0)
    lora_spi.write(bytes([reg | 0x80, val]))
    lora_cs.value(1)


def _lora_read(reg):
    lora_cs.value(0)
    lora_spi.write(bytes([reg & 0x7F]))
    result = lora_spi.read(1)
    lora_cs.value(1)
    return result[0]


def lora_setup():
    global lora_spi, lora_cs, lora_rst, lora_ok
    try:
        lora_spi  = SPI(0, baudrate=1_000_000, polarity=0, phase=0,
                        sck=Pin(LORA_SCK), mosi=Pin(LORA_MOSI), miso=Pin(LORA_MISO))
        lora_cs   = Pin(LORA_CS,   Pin.OUT)
        lora_rst  = Pin(LORA_RST,  Pin.OUT)
        lora_dio0 = Pin(LORA_DIO0, Pin.IN)

        lora_rst.value(0); time.sleep(0.1)
        lora_rst.value(1); time.sleep(0.1)

        version = _lora_read(_REG_VERSION)
        if version != 0x12:
            print(f"[LoRa] Unexpected version {version:#04x} — check wiring")
            return False

        _lora_write(_REG_OP_MODE, _MODE_LONG_RANGE | _MODE_SLEEP)
        time.sleep(0.01)

        frf = int((LORA_FREQ * 1_000_000) / 61.035)
        _lora_write(_REG_FR_MSB, (frf >> 16) & 0xFF)
        _lora_write(_REG_FR_MID, (frf >>  8) & 0xFF)
        _lora_write(_REG_FR_LSB,  frf        & 0xFF)

        _lora_write(_REG_PA_CONFIG, 0x8F)
        _lora_write(_REG_SYNC_WORD, 0x12)
        _lora_write(_REG_OP_MODE,   _MODE_LONG_RANGE | _MODE_STDBY)

        lora_ok = True
        print(f"[LoRa] Initialised at {LORA_FREQ} MHz")
        return True

    except Exception as e:
        print(f"[LoRa] Setup failed: {e}")
        return False


def lora_send(payload: str):
    if not lora_ok:
        return
    try:
        data = payload.encode()[:255]
        _lora_write(_REG_OP_MODE,       _MODE_LONG_RANGE | _MODE_STDBY)
        _lora_write(_REG_FIFO_ADDR_PTR, 0x00)
        _lora_write(_REG_FIFO_TX_BASE,  0x00)
        _lora_write(_REG_FIFO_ADDR_PTR, 0x00)
        for byte in data:
            _lora_write(_REG_FIFO, byte)
        _lora_write(_REG_PAYLOAD_LEN, len(data))
        _lora_write(_REG_OP_MODE, _MODE_LONG_RANGE | _MODE_TX)
        for _ in range(50):
            if _lora_read(_REG_IRQ_FLAGS) & 0x08:
                break
            time.sleep(0.01)
        _lora_write(_REG_IRQ_FLAGS, 0xFF)
        _lora_write(_REG_OP_MODE,   _MODE_LONG_RANGE | _MODE_RXCONT)
    except Exception as e:
        print(f"[LoRa] Send error: {e}")


def lora_receive():
    """Check if a LoRa packet arrived. Returns string or None."""
    if not lora_ok:
        return None
    try:
        irq = _lora_read(_REG_IRQ_FLAGS)
        if not (irq & 0x40):
            return None
        _lora_write(_REG_IRQ_FLAGS, 0xFF)
        nb   = _lora_read(_REG_RX_NB_BYTES)
        addr = _lora_read(_REG_FIFO_RX_CURR)
        _lora_write(_REG_FIFO_ADDR_PTR, addr)
        data = bytearray()
        for _ in range(nb):
            data.append(_lora_read(_REG_FIFO))
        return data.decode("utf-8", "ignore")
    except Exception as e:
        print(f"[LoRa] Receive error: {e}")
        return None


def lora_broadcast_hello():
    payload = build_hello_payload(PROTOCOL_LORA)
    lora_send(payload)
    print(f"[LoRa] Hello broadcast from {NODE_ID:#04x}")


def lora_send_to_gateway():
    pkt     = make_packet(GATEWAY_ID, PROTOCOL_LORA)
    payload = build_data_payload(pkt)
    lora_send(payload)
    print(f"[LoRa] Data seq={pkt.seq_num} → Gateway")


def lora_listener():
    """Poll LoRa for incoming packets — runs in main loop."""
    raw = lora_receive()
    if not raw:
        return
    try:
        msg = json.loads(raw)
        if msg.get("type") == "HELLO":
            nid = msg["node_id"]
            routing_table.update_route(nid, 0, 0, 0.2, PROTOCOL_LORA)
            print(f"[LoRa] Hello from {nid:#04x}")
        elif msg.get("type") == "DATA":
            handle_received_data(msg, "LoRa")
        elif msg.get("type") == "ACK":
            sent    = msg.get("send_time_ms", 0)
            latency = utime.ticks_diff(utime.ticks_ms(), sent)
            seq     = msg.get("seq_num", -1)
            metrics.record_receive(seq)
            print(f"[LoRa] ACK seq={seq}  latency={latency}ms")
    except Exception as e:
        print(f"[LoRa] Parse error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global _ble_reconnect_needed, my_ip

    print(f"[Node] Mesh Node {NODE_ID:#04x} starting...")

    wlan, my_ip = wifi_connect()
    if my_ip:
        wifi_setup(my_ip)
        _thread.start_new_thread(wifi_listener, ())
        print("[Node] WiFi listener started")

    ble_setup()   # FIX: no longer assigns return value; _ble_char_handle set inside

    lora_setup()
    if lora_ok:
        _lora_write(_REG_OP_MODE, _MODE_LONG_RANGE | _MODE_RXCONT)

    print(f"[Node] All protocols initialised. Running...\n")

    last_hello  = 0
    last_packet = 0

    while True:
        now = time.time()

        # FIX: Re-advertise after BLE disconnect safely outside IRQ
        if _ble_reconnect_needed:
            _ble_reconnect_needed = False
            try:
                ble.gap_advertise(100_000, _ble_build_adv_data())
                print("[BLE] Re-advertising after disconnect")
            except Exception as e:
                print(f"[BLE] Re-advertise error: {e}")

        # Hello broadcasts on all available protocols
        if now - last_hello >= HELLO_INTERVAL:
            if my_ip:
                wifi_broadcast_hello(my_ip)
            ble_broadcast_hello()
            lora_broadcast_hello()
            last_hello = now

        # Send data packet via best protocol
        if now - last_packet >= PACKET_INTERVAL:
            send_data()
            last_packet = now

        # Poll LoRa for incoming packets
        lora_listener()

        time.sleep(0.05)


if __name__ == "__main__":
    main()