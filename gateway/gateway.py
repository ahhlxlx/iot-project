"""
gateway/gateway.py  —  Run on Raspberry Pi 4
Receives packets from all 3 protocols simultaneously:
  - WiFi nodes  → UDP socket (port 5005)
  - BLE nodes   → bleak GATT central (async scan + connect + subscribe)
  - LoRa nodes  → SX1276 SPI module (via spidev)

Install dependencies:
  pip3 install flask bleak spidev RPi.GPIO --break-system-packages

Environment variables (set in .env or export before running):
  LORA_FREQ   — LoRa frequency in MHz (default: 915)
  LORA_CS_PIN — BCM GPIO pin for LoRa CS (default: 25)
  LORA_RST_PIN— BCM GPIO pin for LoRa RST (default: 17)
  API_PORT    — Flask API port (default: 8080)
  UDP_PORT    — UDP listen port (default: 5005)
"""

import os
import socket
import json
import time
import asyncio
import threading
import logging
from datetime import datetime
from flask import Flask, jsonify

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — read from environment, never hardcoded
# ─────────────────────────────────────────────────────────────────────────────
UDP_PORT        = int(os.environ.get("UDP_PORT",    5005))
API_PORT        = int(os.environ.get("API_PORT",    8080))
LORA_FREQ       = int(os.environ.get("LORA_FREQ",   915))
LORA_CS_PIN     = int(os.environ.get("LORA_CS_PIN", 25))
LORA_RST_PIN    = int(os.environ.get("LORA_RST_PIN",17))
LORA_SPI_BUS    = int(os.environ.get("LORA_SPI_BUS",   0))
LORA_SPI_DEVICE = int(os.environ.get("LORA_SPI_DEVICE",0))
GATEWAY_ID      = 0xFF

# BLE
_MESH_CHAR_UUID   = "00002a56-0000-1000-8000-00805f9b34fb"
BLE_SCAN_TIMEOUT  = 3.0    # seconds per scan pass
BLE_SCAN_INTERVAL = 5.0    # seconds between scan passes
# ─────────────────────────────────────────────────────────────────────────────


# ── Thread-safe stats ────────────────────────────────────────────────────────
stats_lock = threading.Lock()
stats = {
    "wifi" : {"rx": 0, "lost": 0, "total_latency": 0, "last_seq": -1,
               "min_lat": float("inf"), "max_lat": 0, "rssi_sum": 0},
    "ble"  : {"rx": 0, "lost": 0, "total_latency": 0, "last_seq": -1,
               "min_lat": float("inf"), "max_lat": 0, "rssi_sum": 0},
    "lora" : {"rx": 0, "lost": 0, "total_latency": 0, "last_seq": -1,
               "min_lat": float("inf"), "max_lat": 0, "rssi_sum": 0},
}
PROTO_MAP = {1: "ble", 2: "wifi", 3: "lora"}
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# SHARED PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

def process_packet(msg: dict, sender_label: str = "?"):
    """
    Called by all 3 protocol listeners.
    Updates stats and detects packet loss.
    """
    ptype      = msg.get("type")
    protocol   = msg.get("protocol", 2)
    proto_name = PROTO_MAP.get(protocol, "wifi")

    if ptype == "HELLO":
        node_id = msg.get("node_id", "?")
        log.info("[%s] HELLO  node=%s  from=%s", proto_name.upper(), node_id, sender_label)
        return

    if ptype != "DATA":
        return

    seq       = msg.get("seq_num", -1)
    src       = msg.get("src_id", "?")
    hops      = msg.get("hop_count", 0)
    path      = msg.get("path", [])
    send_time = msg.get("send_time_ms", int(time.time() * 1000))
    rssi      = msg.get("rssi", 0)
    recv_time = int(time.time() * 1000)

    # Guard against Pico ticks_ms vs unix epoch mismatch
    latency = recv_time - send_time
    if latency < 0 or latency > 60_000:
        latency = 0

    with stats_lock:
        s = stats[proto_name]

        # Detect lost packets — gaps > 10 are cross-protocol seq jumps not loss
        if s["last_seq"] >= 0:
            gap = seq - s["last_seq"] - 1
            if gap > 2:
                s["lost"] += gap
                log.warning("[%s] lost %d packet(s)", proto_name, gap)

        s["rx"]            += 1
        s["total_latency"] += latency
        s["min_lat"]        = min(s["min_lat"], latency)
        s["max_lat"]        = max(s["max_lat"], latency)
        s["rssi_sum"]      += rssi
        s["last_seq"]       = seq

    path_str = " → ".join(str(n) for n in path) if path else "?"
    log.info("[%s] DATA  src=%s  seq=%d  hops=%d  latency=%dms  path=[%s]",
             proto_name.upper(), src, seq, hops, latency, path_str)


def send_ack(sock, dest_ip: str, seq: int, send_time_ms: int, src_id):
    """Send ACK back to the correct source node."""
    ack = json.dumps({
        "type"        : "ACK",
        "dest_id"     : src_id,
        "seq_num"     : seq,
        "send_time_ms": send_time_ms,
        "timestamp"   : int(time.time() * 1000),
    }).encode()
    try:
        sock.sendto(ack, (dest_ip, UDP_PORT))
    except OSError as e:
        log.error("[WiFi] ACK error: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# WIFI LISTENER
# ══════════════════════════════════════════════════════════════════════════════

def wifi_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    sock.settimeout(1.0)
    log.info("[WiFi] Listening on UDP port %d", UDP_PORT)

    while True:
        try:
            data, addr    = sock.recvfrom(4096)
            sender_ip     = addr[0]
            msg           = json.loads(data.decode())
            process_packet(msg, sender_ip)
            if msg.get("type") == "DATA":
                send_ack(sock, sender_ip,
                         msg.get("seq_num", -1),
                         msg.get("send_time_ms", 0),
                         msg.get("src_id", 0xFF))
        except socket.timeout:
            pass
        except json.JSONDecodeError:
            log.warning("[WiFi] Non-JSON packet from %s — ignored", addr[0])
        except Exception as e:
            log.error("[WiFi] Error: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# BLE LISTENER  (bleak — cross-platform, actively maintained)
# ══════════════════════════════════════════════════════════════════════════════

def ble_listener():
    try:
        from bleak import BleakScanner, BleakClient
        from bleak.exc import BleakError
    except ImportError:
        log.error("[BLE] bleak not installed — run: pip3 install bleak --break-system-packages")
        return

    async def ble_loop():
        connected_clients: dict = {}

        while True:
            try:
                log.info("[BLE] Scanning for MeshNode_* devices...")
                devices = await BleakScanner.discover(timeout=BLE_SCAN_TIMEOUT)

                for d in devices:
                    name = d.name or ""
                    if not name.startswith("MeshNode_"):
                        continue

                    addr = d.address
                    if addr in connected_clients and connected_clients[addr].is_connected:
                        continue

                    log.info("[BLE] Found %s at %s — connecting...", name, addr)
                    try:
                        client = BleakClient(addr, timeout=20.0)
                        await client.connect()

                        if not client.is_connected:
                            log.warning("[BLE] Failed to connect to %s", addr)
                            continue

                        async def make_notify_handler(device_addr):
                            async def on_notify(sender, data: bytearray):
                                try:
                                    msg = json.loads(data.decode("utf-8", "ignore"))
                                    process_packet(msg, f"BLE:{device_addr}")
                                except Exception as e:
                                    log.error("[BLE] Parse error from %s: %s", device_addr, e)
                            return on_notify

                        handler = await make_notify_handler(addr)
                        await client.start_notify(_MESH_CHAR_UUID, handler)
                        connected_clients[addr] = client
                        log.info("[BLE] Subscribed to notifications from %s", name)

                    except BleakError as e:
                        log.error("[BLE] Connect error (%s): %s", addr, e)
                    except Exception as e:
                        log.error("[BLE] Unexpected connect error (%s): %s", addr, e)

                # Clean up disconnected clients
                to_remove = [a for a, c in connected_clients.items() if not c.is_connected]
                for addr in to_remove:
                    log.info("[BLE] %s disconnected — will re-scan", addr)
                    del connected_clients[addr]

                await asyncio.sleep(BLE_SCAN_INTERVAL)

            except Exception as e:
                log.error("[BLE] Loop error: %s", e)
                await asyncio.sleep(2)

    asyncio.run(ble_loop())   # ← must be INSIDE ble_listener, at the bottom


# ══════════════════════════════════════════════════════════════════════════════
# LORA LISTENER (SX1276 SPI on RPi4)
# ══════════════════════════════════════════════════════════════════════════════

_REG_FIFO          = 0x00
_REG_OP_MODE       = 0x01
_REG_FR_MSB        = 0x06
_REG_FR_MID        = 0x07
_REG_FR_LSB        = 0x08
_REG_IRQ_FLAGS     = 0x12
_REG_RX_NB_BYTES   = 0x13
_REG_PKT_RSSI      = 0x1A
_REG_FIFO_ADDR_PTR = 0x0D
_REG_FIFO_RX_BASE  = 0x0F
_REG_FIFO_RX_CURR  = 0x10
_REG_SYNC_WORD     = 0x39
_REG_VERSION       = 0x42
_MODE_SLEEP        = 0x00
_MODE_STDBY        = 0x01
_MODE_RXCONT       = 0x05
_MODE_LONG_RANGE   = 0x80

lora_spi  = None
lora_gpio = None
lora_ok   = False


def lora_write(reg, val):
    lora_gpio.output(LORA_CS_PIN, lora_gpio.LOW)
    lora_spi.xfer2([reg | 0x80, val])
    lora_gpio.output(LORA_CS_PIN, lora_gpio.HIGH)


def lora_read(reg):
    lora_gpio.output(LORA_CS_PIN, lora_gpio.LOW)
    result = lora_spi.xfer2([reg & 0x7F, 0x00])
    lora_gpio.output(LORA_CS_PIN, lora_gpio.HIGH)
    return result[1]


def lora_setup():
    global lora_spi, lora_gpio, lora_ok
    try:
        import spidev
        import RPi.GPIO as GPIO

        lora_gpio = GPIO
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(LORA_CS_PIN,  GPIO.OUT)
        GPIO.setup(LORA_RST_PIN, GPIO.OUT)

        lora_spi = spidev.SpiDev()
        lora_spi.open(LORA_SPI_BUS, LORA_SPI_DEVICE)
        lora_spi.max_speed_hz = 1_000_000

        # Longer reset pulse for reliability
        GPIO.output(LORA_RST_PIN, GPIO.LOW);  time.sleep(0.1)
        GPIO.output(LORA_RST_PIN, GPIO.HIGH); time.sleep(0.1)

        version = lora_read(_REG_VERSION)
        if version != 0x12:
            log.warning("[LoRa] Version %s unexpected — check wiring", hex(version))
            return False

        lora_write(_REG_OP_MODE, _MODE_LONG_RANGE | _MODE_SLEEP); time.sleep(0.01)

        frf = int((LORA_FREQ * 1_000_000) / 61.035)
        lora_write(_REG_FR_MSB, (frf >> 16) & 0xFF)
        lora_write(_REG_FR_MID, (frf >>  8) & 0xFF)
        lora_write(_REG_FR_LSB,  frf        & 0xFF)

        lora_write(_REG_SYNC_WORD,     0x12)
        lora_write(_REG_FIFO_RX_BASE,  0x00)
        lora_write(_REG_FIFO_ADDR_PTR, 0x00)
        lora_write(_REG_OP_MODE, _MODE_LONG_RANGE | _MODE_RXCONT)

        lora_ok = True
        log.info("[LoRa] Initialised at %d MHz", LORA_FREQ)
        return True

    except ImportError:
        log.warning("[LoRa] spidev/RPi.GPIO not installed — skipping LoRa listener")
        return False
    except Exception as e:
        log.error("[LoRa] Setup failed: %s", e)
        return False


def lora_listener():
    if not lora_ok:
        return
    log.info("[LoRa] Listener polling...")
    while True:
        try:
            irq = lora_read(_REG_IRQ_FLAGS)
            if irq & 0x40:   # RxDone bit
                lora_write(_REG_IRQ_FLAGS, 0xFF)
                nb   = lora_read(_REG_RX_NB_BYTES)
                addr = lora_read(_REG_FIFO_RX_CURR)
                lora_write(_REG_FIFO_ADDR_PTR, addr)
                data = bytearray()
                for _ in range(nb):
                    data.append(lora_read(_REG_FIFO))
                rssi = lora_read(_REG_PKT_RSSI) - 157
                try:
                    msg = json.loads(data.decode("utf-8", "ignore"))
                    msg["rssi"] = rssi
                    process_packet(msg, f"LoRa RSSI={rssi}")
                except Exception as e:
                    log.error("[LoRa] Parse error: %s", e)
        except Exception as e:
            log.error("[LoRa] Poll error: %s", e)
        time.sleep(0.05)


# ══════════════════════════════════════════════════════════════════════════════
# FLASK REST API
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)


@app.route("/api/stats")
def api_stats():
    """Live in-memory stats for all 3 protocols."""
    with stats_lock:
        result     = {}
        best_proto = None
        best_cost  = float("inf")

        for proto, s in stats.items():
            rx   = s["rx"]
            lost = s["lost"]
            loss = (lost / (rx + lost) * 100) if (rx + lost) > 0 else 0.0
            avg  = (s["total_latency"] / rx)  if rx > 0 else 0
            rssi = (s["rssi_sum"] / rx)        if rx > 0 else 0
            power = {"wifi": 1, "ble": 2, "lora": 3}[proto]
            cost  = (0.5 * avg) + (30 * loss) + (10 * power)

            result[proto] = {
                "packets_received": rx,
                "packet_loss_pct" : round(loss, 2),
                "avg_latency_ms"  : round(avg,  1),
                "min_latency_ms"  : s["min_lat"] if s["min_lat"] != float("inf") else 0,
                "max_latency_ms"  : s["max_lat"],
                "avg_rssi"        : round(rssi, 1),
                "cost_score"      : round(cost, 2),
            }
            if cost < best_cost:
                best_cost  = cost
                best_proto = proto

    return jsonify({
        "protocols":     result,
        "best_protocol": best_proto,
        "timestamp":     datetime.now().isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    threading.Thread(target=wifi_listener, daemon=True).start()
    threading.Thread(target=ble_listener,  daemon=True).start()

    if lora_setup():
        threading.Thread(target=lora_listener, daemon=True).start()
    else:
        log.warning("[LoRa] Disabled — check wiring or SPI config")

    log.info("=" * 55)
    log.info(" IoT Mesh Gateway  —  Raspberry Pi 4")
    log.info(" API: http://localhost:%d/api/stats", API_PORT)
    log.info("=" * 55)

    app.run(host="0.0.0.0", port=API_PORT, debug=False)


if __name__ == "__main__":
    main()