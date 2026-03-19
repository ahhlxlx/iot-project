"""
╔══════════════════════════════════════════════════════════════════╗
║       IoT Mesh Network Node  –  Maker Pi Pico W                 ║
║       Dual-Protocol: WiFi  +  BLE  (both carry real data)       ║
╠══════════════════════════════════════════════════════════════════╣
║  HOW IT WORKS:                                                   ║
║  Each node sends the SAME metric packet over BOTH WiFi AND BLE  ║
║  independently. The gateway receives both copies and compares   ║
║  performance. The routing table tracks cost PER PROTOCOL PER    ║
║  LINK so the node always knows:                                 ║
║    • Which neighbour is the best next hop                       ║
║    • Whether to reach it via WiFi or BLE                        ║
║                                                                  ║
║  Routing Table (per destination):                               ║
║  Dest | Next Hop | Best Protocol | Hops | Latency | Cost        ║
║       |          | WiFi cost vs BLE cost  (compared live)       ║
╚══════════════════════════════════════════════════════════════════╝

MicroPython v1.22+ required  (network + ubluetooth modules)
Upload as main.py to Pico W to auto-start on boot.
"""

import network
import ubluetooth
import socket
import time
import json
import machine
from micropython import const

# ══════════════════════════════════════════════
#  ① NODE CONFIGURATION  ← edit per device
# ══════════════════════════════════════════════
NODE_ID        = "NODE_lx"       # Change to NODE_02, NODE_03 … for each Pico W
GATEWAY_IP     = "10.200.176.43"   # Raspberry Pi IP
WIFI_SSID      = "OnePlus13Equals14"       # Shared WiFi network name
WIFI_PASSWORD  = "gkpm5847"   # Shared WiFi password

# Cost function weights  (must sum to 1.0)
W_LATENCY      = 0.5             # Higher = prioritise low latency
W_PACKET_LOSS  = 0.3             # Higher = prioritise reliability
W_POWER        = 0.2             # Higher = prioritise battery saving

# Timing (seconds)
HELLO_INTERVAL  = 5              # Neighbour discovery broadcast interval
METRIC_INTERVAL = 10             # How often to send metrics to gateway
PING_INTERVAL   = 8              # How often to probe neighbour RTT
ROUTE_TIMEOUT   = 45             # Drop neighbour if silent for this long

# Ports
UDP_MESH_PORT   = 5005           # Node-to-node mesh communication
UDP_GW_PORT     = 5006           # Node-to-gateway data delivery

# BLE packet type constants
BLE_MAGIC           = b'\xAA\xBB'
BLE_PKT_TYPE_HELLO  = 0x01
BLE_PKT_TYPE_METRIC = 0x02
BLE_PKT_TYPE_PING   = 0x03
BLE_PKT_TYPE_PONG   = 0x04


# ══════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════

# Per-link measurements, keyed by (node_id, protocol)
# {
#   ("NODE_02", "WiFi"): {
#       "ip": "192.168.4.3",
#       "rssi": -65,
#       "last_seen": 1234567.0,
#       "latency_samples": [12.1, 13.5, ...],
#       "sent_count": 10,
#       "recv_count": 9,
#       "packet_loss": 0.10,
#       "power_cost": 0.3
#   },
#   ("NODE_02", "BLE"): { ... }
# }
link_stats = {}

# Routing table – one BEST entry per destination
# {
#   "NODE_02": {
#       "next_hop"      : "NODE_02",
#       "best_protocol" : "WiFi",      ← THE KEY OUTPUT: which protocol to use
#       "hop_count"     : 1,
#       "avg_latency_ms": 14.2,
#       "packet_loss"   : 0.01,
#       "cost"          : 7.43,        ← best (lowest) cost
#       "wifi_cost"     : 7.43,        ← WiFi-specific cost
#       "ble_cost"      : 22.10,       ← BLE-specific cost
#       "wifi_lat"      : 14.2,
#       "ble_lat"       : 44.8,
#   }
# }
routing_table = {}

seq_number   = 0
wlan         = None
udp_sock     = None
ble_obj      = None
my_ip        = "0.0.0.0"

# Protocol availability flags – set during startup, re-checked in main loop
wifi_active  = False   # True once WiFi is connected and UDP socket is open
ble_active   = False   # True once BLE is initialised

# BLE receive buffer filled by IRQ, drained in main loop
ble_rx_buffer = []

# BLE print throttle: only print every BLE_PRINT_EVERY messages per node
BLE_PRINT_EVERY = 10
ble_recv_count  = {}   # { node_id: int }

# Pending PING timestamps: { (node_id, protocol): sent_time }
ping_pending = {}

last_hello_time  = 0
last_metric_time = 0
last_ping_time   = 0


# ══════════════════════════════════════════════
#  WIFI
# ══════════════════════════════════════════════

def connect_wifi():
    global wlan, my_ip, wifi_active
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(WIFI_SSID, WIFI_PASSWORD)
    print(f"[WiFi] Connecting to '{WIFI_SSID}' ...")
    for _ in range(20):
        if wlan.isconnected():
            break
        time.sleep(1)
    if wlan.isconnected():
        my_ip = wlan.ifconfig()[0]
        wifi_active = True
        print(f"[WiFi] Connected  IP={my_ip}")
        return True
    wifi_active = False
    print("[WiFi] FAILED – running in BLE-only mode")
    return False


def wifi_rssi():
    try:
        if wifi_active and wlan and wlan.isconnected():
            return wlan.status('rssi')
    except Exception:
        pass
    return -99


def check_wifi_reconnect():
    """
    Non-blocking WiFi reconnect attempt.
    Just calls connect() and checks status immediately —
    the actual connection happens in the background.
    BLE operation is NOT paused during this call.
    """
    global wifi_active, udp_sock, my_ip
    if wifi_active and wlan and wlan.isconnected():
        return  # all good

    # If already trying to connect, just check if it succeeded
    if wlan and wlan.isconnected():
        my_ip = wlan.ifconfig()[0]
        wifi_active = True
        if udp_sock is None:
            setup_udp()
        print(f"[WiFi] Reconnected  IP={my_ip}")
        return

    # Trigger a new connection attempt (non-blocking — returns immediately)
    try:
        print("[WiFi] Attempting reconnect (background)...")
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
        # Don't wait here — result checked on next retry cycle
    except Exception as e:
        print(f"[WiFi] Reconnect trigger error: {e}")


# ══════════════════════════════════════════════
#  UDP SOCKET
# ══════════════════════════════════════════════

def setup_udp():
    global udp_sock
    if not wifi_active:
        print("[UDP]  Skipped – no WiFi")
        return
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind(("0.0.0.0", UDP_MESH_PORT))
        udp_sock.setblocking(False)
        print(f"[UDP]  Listening on port {UDP_MESH_PORT}")
    except Exception as e:
        print(f"[UDP]  Setup failed: {e}")
        udp_sock = None


def udp_send(ip, port, obj):
    if not wifi_active or udp_sock is None:
        return False
    try:
        udp_sock.sendto(json.dumps(obj).encode(), (ip, port))
        return True
    except Exception as e:
        print(f"[UDP]  Send error: {e}")
        return False


def udp_broadcast(port, obj):
    if not wifi_active or udp_sock is None:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(json.dumps(obj).encode(), ("255.255.255.255", port))
        s.close()
        return True
    except Exception as e:
        print(f"[UDP]  Broadcast error: {e}")
        return False


# ══════════════════════════════════════════════
#  BLE PACKET ENCODING / DECODING
#
#  We embed compact metrics in BLE manufacturer-specific
#  advertisement data (max ~20 usable bytes).
#
#  Layout (19 bytes):
#   [0-1]  magic 0xAA 0xBB
#   [2]    packet type (HELLO/METRIC/PING/PONG)
#   [3-9]  sender NODE_ID (7 bytes ASCII, zero-padded)
#   [10]   seq/hop number (uint8, wraps at 255)
#   [11-14] timestamp low 32-bits (big-endian uint32)
#   [15]   RSSI shifted  (rssi + 128, so -128..+127 → 0..255)
#   [16-17] latency * 10 (uint16, max 6553.5 ms)
#   [18]   packet loss * 255 (uint8)
# ══════════════════════════════════════════════

def encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct):
    # MicroPython: bytes has no .ljust() — pad manually
    raw_b   = NODE_ID.encode()[:7]
    node_b  = raw_b + b'\x00' * (7 - len(raw_b))
    ts_int  = int(ts) & 0xFFFFFFFF
    rssi_b  = (rssi + 128) & 0xFF
    lat_b   = min(65535, int(lat_ms * 10))
    loss_b  = min(255, int(loss_pct * 255))
    return (BLE_MAGIC
            + bytes([pkt_type])
            + node_b
            + bytes([seq_hop & 0xFF])
            + ts_int.to_bytes(4, 'big')
            + bytes([rssi_b, (lat_b >> 8) & 0xFF, lat_b & 0xFF, loss_b]))


def decode_ble(raw):
    try:
        b = bytes(raw)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None
        return {
            "pkt_type": b[2],
            "node_id" : b[3:10].rstrip(b'\x00').decode('utf-8'),
            "seq_hop" : b[10],
            "ts"      : int.from_bytes(b[11:15], 'big'),
            "rssi"    : b[15] - 128,
            "lat_ms"  : ((b[16] << 8) | b[17]) / 10.0,
            "loss"    : b[18] / 255.0
        }
    except Exception:
        return None


def find_manuf_data(adv_data):
    """Extract type-0xFF manufacturer data from raw BLE advertisement."""
    b   = bytes(adv_data)
    idx = 0
    while idx < len(b) - 1:
        length  = b[idx]
        if length == 0:
            break
        ad_type = b[idx + 1]
        if ad_type == 0xFF and length >= 3:
            return b[idx + 2: idx + 1 + length]
        idx += 1 + length
    return None


def valid_node_id(node_id):
    """
    Accept only node IDs matching our format: NODE_XX (7 chars max).
    Rejects rogue devices, junk BLE advertisers, or malformed packets.
    """
    if not node_id or len(node_id) > 7:
        return False
    if not node_id.startswith("NODE_"):
        return False
    return True


# ══════════════════════════════════════════════
#  BLE IRQ  (hardware interrupt – keep minimal)
# ══════════════════════════════════════════════

def ble_irq(event, data):
    _IRQ_SCAN_RESULT = const(5)
    if event == _IRQ_SCAN_RESULT:
        addr_type, addr, adv_type, rssi, adv_data = data
        manuf = find_manuf_data(adv_data)
        if manuf and len(manuf) >= 19:
            decoded = decode_ble(manuf)
            if decoded and decoded["node_id"] and decoded["node_id"] != NODE_ID and valid_node_id(decoded["node_id"]):
                decoded["adv_rssi"] = rssi  # RSSI as measured by our radio
                ble_rx_buffer.append(decoded)


# ══════════════════════════════════════════════
#  BLE SETUP
# ══════════════════════════════════════════════

def setup_ble():
    global ble_obj, ble_active
    try:
        ble_obj = ubluetooth.BLE()
        ble_obj.active(True)
        ble_obj.irq(ble_irq)
        ble_obj.gap_scan(0, 100_000, 50_000, False)  # continuous passive scan
        ble_active = True
        print("[BLE]  Scanning started")
    except Exception as e:
        print(f"[BLE]  Setup failed: {e}")
        ble_obj    = None
        ble_active = False


def ble_advertise(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct):
    if not ble_active or ble_obj is None:
        return
    try:
        payload = encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct)
        ad = bytes([len(payload) + 1, 0xFF]) + payload  # wrap in AD structure
        ble_obj.gap_advertise(100_000, adv_data=ad)
    except Exception as e:
        print(f"[BLE]  Advertise error: {e}")


# ══════════════════════════════════════════════
#  LINK STATS HELPERS
# ══════════════════════════════════════════════

def get_link(node_id, protocol):
    key = (node_id, protocol)
    if key not in link_stats:
        link_stats[key] = {
            "ip"              : None,
            "rssi"            : -99,
            "last_seen"       : 0,
            "latency_samples" : [],
            "sent_count"      : 0,
            "recv_count"      : 0,
            "packet_loss"     : 0.0,
            "power_cost"      : 1.0
        }
    return link_stats[key]


def record_latency(node_id, protocol, rtt_ms, rssi):
    lnk = get_link(node_id, protocol)
    lnk["rssi"]      = rssi
    lnk["last_seen"] = time.time()
    lnk["latency_samples"].append(rtt_ms)
    if len(lnk["latency_samples"]) > 10:
        lnk["latency_samples"].pop(0)
    lnk["recv_count"] += 1
    total = lnk["sent_count"]
    if total > 0:
        lnk["packet_loss"] = max(0.0, 1.0 - lnk["recv_count"] / total)
    # Power cost: weaker RSSI = more TX power needed
    # -50dBm (strong) → 0.05,  -90dBm (weak) → 1.0
    lnk["power_cost"] = min(1.0, max(0.05, (-rssi - 50) / 40.0))


def avg_latency(node_id, protocol):
    samples = get_link(node_id, protocol)["latency_samples"]
    return sum(samples) / len(samples) if samples else 9999.0


# ══════════════════════════════════════════════
#  COST FUNCTION
# ══════════════════════════════════════════════

def compute_cost(latency_ms, packet_loss, power_cost):
    """
    Lower cost = better path.
      latency_ms  : average RTT in ms  (normalised /100 so 100ms = weight of 1.0)
      packet_loss : 0.0 – 1.0
      power_cost  : 0.0 – 1.0
    Example:
      WiFi: cost = 0.5*(14/100) + 0.3*0.01 + 0.2*0.15 = 0.07 + 0.003 + 0.03 = 0.103
      BLE:  cost = 0.5*(45/100) + 0.3*0.02 + 0.2*0.40 = 0.225 + 0.006 + 0.08 = 0.311
      → WiFi wins
    """
    return W_LATENCY * (latency_ms / 100.0) + W_PACKET_LOSS * packet_loss + W_POWER * power_cost


# ══════════════════════════════════════════════
#  ROUTING TABLE  –  rebuild from link_stats
# ══════════════════════════════════════════════

def rebuild_routing_table():
    """
    For every direct neighbour compare WiFi cost vs BLE cost.
    Elect the lower-cost protocol as best_protocol for that link.
    This runs after every new latency/RSSI measurement.
    """
    now = time.time()
    seen_nodes = set(n for (n, _) in link_stats.keys())

    for node_id in seen_nodes:
        wifi_lnk = get_link(node_id, "WiFi")
        ble_lnk  = get_link(node_id, "BLE")

        wifi_fresh = now - wifi_lnk["last_seen"] < ROUTE_TIMEOUT
        ble_fresh  = now - ble_lnk["last_seen"]  < ROUTE_TIMEOUT

        if not wifi_fresh and not ble_fresh:
            continue  # stale node – will be pruned

        # Compute per-protocol costs
        wifi_lat  = avg_latency(node_id, "WiFi")
        # BLE is one-way broadcast so RTT is not measurable.
        # Estimate BLE latency from RSSI when no samples exist:
        #   -40dBm (strong) -> ~25ms,  -80dBm (weak) -> ~80ms
        ble_rssi  = ble_lnk["rssi"]
        if ble_lnk["latency_samples"]:
            ble_lat = avg_latency(node_id, "BLE")
        elif ble_rssi > -99:
            ble_lat = max(20.0, min(120.0, (ble_rssi + 40) * -1.375 + 25))
        else:
            ble_lat = 9999.0
        wifi_cost = compute_cost(wifi_lat, wifi_lnk["packet_loss"], wifi_lnk["power_cost"]) if wifi_fresh else 9999
        ble_cost  = compute_cost(ble_lat,  ble_lnk["packet_loss"],  ble_lnk["power_cost"])  if ble_fresh  else 9999

        # Elect winner
        if wifi_cost <= ble_cost:
            best_proto = "WiFi"
            best_cost  = wifi_cost
            best_lat   = wifi_lat if wifi_fresh else ble_lat
            best_loss  = wifi_lnk["packet_loss"]
            best_power = wifi_lnk["power_cost"]
        else:
            best_proto = "BLE"
            best_cost  = ble_cost
            best_lat   = ble_lat if ble_fresh else wifi_lat
            best_loss  = ble_lnk["packet_loss"]
            best_power = ble_lnk["power_cost"]

        routing_table[node_id] = {
            "next_hop"      : node_id,
            "best_protocol" : best_proto,
            "hop_count"     : 1,
            "avg_latency_ms": round(best_lat, 2) if best_lat < 9999 else 0,
            "packet_loss"   : round(best_loss, 4),
            "power_cost"    : round(best_power, 4),
            "cost"          : round(best_cost, 6),
            "wifi_cost"     : round(wifi_cost, 6) if wifi_fresh else None,
            "ble_cost"      : round(ble_cost,  6) if ble_fresh  else None,
            "wifi_lat"      : round(wifi_lat, 2)  if wifi_fresh else None,
            "ble_lat"       : round(ble_lat, 2)   if ble_fresh  else None,
            "last_seen"     : now
        }


def learn_indirect_routes(sender_id, sender_routing, my_cost_to_sender):
    """
    Distance-vector: if sender knows a route to node X,
    we can reach X by going via sender (extra hop).
    We only accept if cheaper than any existing route.
    """
    for dest, info in sender_routing.items():
        if dest == NODE_ID:
            continue
        if not valid_node_id(dest):
            continue   # reject rogue / foreign node IDs from other teams
        their_cost  = info.get("cost", 9999)
        new_hops    = info.get("hop_count", 99) + 1
        new_lat     = info.get("avg_latency_ms", 9999) + avg_latency(sender_id, "WiFi")
        new_loss    = max(info.get("packet_loss", 0), get_link(sender_id, "WiFi")["packet_loss"])
        new_cost    = compute_cost(new_lat, new_loss, 0.5)

        existing = routing_table.get(dest)
        if existing is None or new_cost < existing.get("cost", 9999):
            routing_table[dest] = {
                "next_hop"      : sender_id,         # go via this neighbour
                "best_protocol" : info.get("best_protocol", "WiFi"),
                "hop_count"     : new_hops,
                "avg_latency_ms": round(new_lat, 2),
                "packet_loss"   : round(new_loss, 4),
                "power_cost"    : 0.5,
                "cost"          : round(new_cost, 6),
                "wifi_cost"     : round(new_cost, 6),
                "ble_cost"      : round(new_cost + 0.2, 6),
                "wifi_lat"      : round(new_lat, 2),
                "ble_lat"       : round(new_lat + 20, 2),
                "last_seen"     : time.time()
            }
            print(f"[Route] Indirect route: {dest} via {sender_id}  hops={new_hops}  cost={new_cost:.4f}")


def prune_stale_routes():
    now = time.time()
    stale_links  = [k for k, v in link_stats.items()  if now - v["last_seen"] > ROUTE_TIMEOUT]
    stale_routes = [k for k, v in routing_table.items() if now - v["last_seen"] > ROUTE_TIMEOUT]
    for k in stale_links:
        del link_stats[k]
        print(f"[Route] Pruned stale link {k[0]} / {k[1]}")
    for k in stale_routes:
        del routing_table[k]
        print(f"[Route] Pruned stale route → {k}")


# ══════════════════════════════════════════════
#  ROUTING TABLE PRETTY PRINT
# ══════════════════════════════════════════════

def print_routing_table():
    print()
    print("┌──────────────────────────────────────────────────────────────────────────────┐")
    print(f"│  ROUTING TABLE  [{NODE_ID}]  –  Best next hop + protocol per destination  │")
    print("├────────────┬────────────┬───────────────┬──────┬────────────┬───────────────┤")
    print("│ Dest       │ Next Hop   │ Best Protocol │ Hops │ Latency ms │ Cost          │")
    print("│            │            │ (WiFi vs BLE) │      │            │ (lower=better)│")
    print("├────────────┼────────────┼───────────────┼──────┼────────────┼───────────────┤")

    if not routing_table:
        print("│  (no routes yet – waiting for neighbour discovery)                          │")
    else:
        for dest in sorted(routing_table.keys()):
            r       = routing_table[dest]
            proto   = r["best_protocol"]
            w_cost  = r.get("wifi_cost")
            b_cost  = r.get("ble_cost")
            w_lat   = r.get("wifi_lat")
            b_lat   = r.get("ble_lat")

            # Winner indicator
            w_tag = " <BEST" if proto == "WiFi" else ""
            b_tag = " <BEST" if proto == "BLE"  else ""

            proto_disp = ("WiFi" if proto == "WiFi" else "BLE ") + " (winner)"
            print(f"│ {dest:<10} │ {r['next_hop']:<10} │ {proto_disp:<13} │ {r['hop_count']:<4} │ "
                  f"{r['avg_latency_ms']:<10.1f} │ {r['cost']:<13.6f} │")

            w_str = f"{w_cost:.4f} lat={w_lat:.0f}ms" if w_cost is not None else "not seen"
            b_str = f"{b_cost:.4f} lat={b_lat:.0f}ms" if b_cost is not None else "not seen"
            print(f"│            │   WiFi: {w_str:<16}{w_tag:<6}  BLE: {b_str:<16}{b_tag:<6}│")

    print("└────────────┴────────────┴───────────────┴──────┴────────────┴───────────────┘")
    print()


# ══════════════════════════════════════════════
#  HELLO BROADCAST  (WiFi + BLE)
# ══════════════════════════════════════════════

def broadcast_hello():
    ts   = time.time()
    rssi = wifi_rssi()

    # Build compact routing snapshot to share with neighbours
    rt_share = {}
    for dest, r in routing_table.items():
        rt_share[dest] = {
            "next_hop"      : r["next_hop"],
            "best_protocol" : r["best_protocol"],
            "hop_count"     : r["hop_count"],
            "avg_latency_ms": r["avg_latency_ms"],
            "packet_loss"   : r["packet_loss"],
            "cost"          : r["cost"]
        }

    # ── WiFi Hello ──────────────────────────────────────────────
    hello = {
        "type"     : "HELLO",
        "node_id"  : NODE_ID,
        "protocol" : "WiFi",
        "timestamp": ts,
        "ip"       : my_ip,
        "rssi"     : rssi,
        "routing"  : rt_share
    }
    udp_broadcast(UDP_MESH_PORT, hello)

    # ── BLE Hello beacon ────────────────────────────────────────
    # Lets BLE-only neighbours or the BLE scanner on the gateway
    # know we exist and measure our BLE signal strength
    ble_samples = [s for (_, p), lnk in link_stats.items()
                   for s in lnk["latency_samples"] if p == "BLE"]
    avg_ble_lat = sum(ble_samples) / len(ble_samples) if ble_samples else 0.0
    ble_advertise(BLE_PKT_TYPE_HELLO, 0, ts, rssi, avg_ble_lat, 0.0)

    neighbours = list(set(n for (n, _) in link_stats.keys()))
    print(f"[Hello] WiFi+BLE broadcast  |  known neighbours: {neighbours}")


# ══════════════════════════════════════════════
#  PING NEIGHBOURS  (measure RTT per protocol)
# ══════════════════════════════════════════════

def ping_all_neighbours():
    now = time.time()

    # WiFi PING to every known WiFi neighbour
    for (node_id, proto), lnk in list(link_stats.items()):
        if proto != "WiFi":
            continue
        if not lnk.get("ip"):
            continue
        if now - lnk["last_seen"] > ROUTE_TIMEOUT:
            continue
        ping_pkt = {
            "type"      : "PING",
            "node_id"   : NODE_ID,
            "protocol"  : "WiFi",
            "timestamp" : now,
            "ticks_ms"  : time.ticks_ms()   # millisecond precision for RTT
        }
        ok = udp_send(lnk["ip"], UDP_MESH_PORT, ping_pkt)
        if ok:
            get_link(node_id, "WiFi")["sent_count"] += 1
            ping_pending[(node_id, "WiFi")] = time.ticks_ms()

    # BLE PING beacon – neighbouring nodes that see this adv
    # respond via WiFi PONG carrying the BLE RSSI they measured,
    # giving us a real BLE link quality measurement
    ble_advertise(BLE_PKT_TYPE_PING, 0, now, wifi_rssi(), 0.0, 0.0)


# ══════════════════════════════════════════════
#  METRIC PACKETS  (WiFi + BLE simultaneously)
# ══════════════════════════════════════════════

def send_metrics():
    global seq_number
    seq_number += 1
    ts   = time.time()
    rssi = wifi_rssi()

    # Aggregate per-protocol metrics
    w_lats = [s for (_, p), lnk in link_stats.items() for s in lnk["latency_samples"] if p == "WiFi"]
    b_lats = [s for (_, p), lnk in link_stats.items() for s in lnk["latency_samples"] if p == "BLE"]
    w_losses = [lnk["packet_loss"] for (_, p), lnk in link_stats.items() if p == "WiFi"]
    b_losses = [lnk["packet_loss"] for (_, p), lnk in link_stats.items() if p == "BLE"]
    b_rssies = [lnk["rssi"]        for (_, p), lnk in link_stats.items() if p == "BLE"]

    avg_w_lat  = sum(w_lats)   / len(w_lats)   if w_lats   else 0.0
    avg_b_lat  = sum(b_lats)   / len(b_lats)   if b_lats   else 0.0
    avg_w_loss = sum(w_losses) / len(w_losses) if w_losses else 0.0
    avg_b_loss = sum(b_losses) / len(b_losses) if b_losses else 0.0
    avg_b_rssi = sum(b_rssies) / len(b_rssies) if b_rssies else -99

    # Full routing snapshot
    rt_snapshot = {}
    for dest, r in routing_table.items():
        rt_snapshot[dest] = {
            "next_hop"      : r["next_hop"],
            "best_protocol" : r["best_protocol"],
            "hop_count"     : r["hop_count"],
            "avg_latency_ms": r["avg_latency_ms"],
            "packet_loss"   : r["packet_loss"],
            "cost"          : r["cost"],
            "wifi_cost"     : r.get("wifi_cost"),
            "ble_cost"      : r.get("ble_cost"),
            "wifi_lat"      : r.get("wifi_lat"),
            "ble_lat"       : r.get("ble_lat"),
        }

    # ── 1. WiFi metric packet → gateway ─────────────────────────
    wifi_pkt = {
        "type"         : "METRIC",
        "node_id"      : NODE_ID,
        "protocol"     : "WiFi",
        "timestamp"    : ts,
        "seq_number"   : seq_number,
        "hop_count"    : 0,
        "rssi"         : rssi,
        "ip"           : my_ip,
        "neighbours"   : list(set(n for (n, _) in link_stats.keys())),
        "routing_table": rt_snapshot,
        "metrics": {
            "wifi_avg_latency_ms": round(avg_w_lat, 2),
            "ble_avg_latency_ms" : round(avg_b_lat, 2),
            "wifi_packet_loss"   : round(avg_w_loss, 4),
            "ble_packet_loss"    : round(avg_b_loss, 4),
            "wifi_rssi"          : rssi,
            "ble_rssi"           : round(avg_b_rssi, 1),
        }
    }
    ok = udp_send(GATEWAY_IP, UDP_GW_PORT, wifi_pkt)
    if ok:
        get_link("GATEWAY", "WiFi")["sent_count"] += 1

    # ── 2. BLE metric advertisement ──────────────────────────────
    # This compact BLE beacon lets the gateway's BLE scanner
    # independently record BLE performance for this node.
    ble_advertise(BLE_PKT_TYPE_METRIC, seq_number & 0xFF,
                  ts, rssi, avg_b_lat, avg_b_loss)

    active = ("WiFi+" if wifi_active else "") + ("BLE" if ble_active else "")
    print(f"[Metric] [{active}] seq={seq_number} wifi_rssi={rssi}dBm  |  "
          f"ble_lat={avg_b_lat:.1f}ms")

    # ── 3. Print routing decision ─────────────────────────────────
    print_routing_table()


# ══════════════════════════════════════════════
#  PROCESS INCOMING WiFi PACKETS
# ══════════════════════════════════════════════

def process_wifi_packets():
    try:
        while True:
            data, addr   = udp_sock.recvfrom(2048)
            sender_ip    = addr[0]
            recv_ts      = time.time()
            try:
                pkt = json.loads(data.decode())
            except Exception:
                continue

            ptype   = pkt.get("type")
            node_id = pkt.get("node_id", "")
            if node_id == NODE_ID or not valid_node_id(node_id):
                continue   # ignore our own reflections and rogue nodes

            if ptype == "HELLO":
                lat_ms = max(0.0, (recv_ts - pkt.get("timestamp", recv_ts)) * 1000)
                record_latency(node_id, "WiFi", lat_ms, pkt.get("rssi", -99))
                get_link(node_id, "WiFi")["ip"] = pkt.get("ip", sender_ip)
                # Learn indirect routes from sender's routing table
                my_cost = routing_table.get(node_id, {}).get("cost", 50.0)
                learn_indirect_routes(node_id, pkt.get("routing", {}), my_cost)
                rebuild_routing_table()

            elif ptype == "PING":
                # Reply with PONG + include the BLE RSSI we measured for that sender
                pong = {
                    "type"              : "PONG",
                    "node_id"           : NODE_ID,
                    "protocol"          : "WiFi",
                    "ping_ts"           : pkt.get("timestamp"),
                    "ping_ticks_ms"     : pkt.get("ticks_ms"),  # echo back for accurate RTT
                    "timestamp"         : recv_ts,
                    "ble_rssi_of_sender": get_link(node_id, "BLE")["rssi"]
                }
                udp_send(sender_ip, UDP_MESH_PORT, pong)

            elif ptype == "PONG":
                # Use ticks_ms for accurate sub-second RTT measurement
                ping_ticks = pkt.get("ping_ticks_ms")
                if ping_ticks is not None:
                    rtt_ms = time.ticks_diff(time.ticks_ms(), ping_ticks)
                else:
                    ping_ts = pkt.get("ping_ts", 0)
                    rtt_ms  = (recv_ts - ping_ts) * 1000 if ping_ts else 0
                rtt_ms = float(rtt_ms)
                # Discard stale PONGs: cap at 400ms on a local network.
                # Silently drop rather than printing to reduce console noise.
                if rtt_ms < 0 or rtt_ms > 400:
                    ping_pending.pop((node_id, "WiFi"), None)
                    continue
                record_latency(node_id, "WiFi", rtt_ms, pkt.get("rssi", wifi_rssi()))
                # Record BLE RSSI reported by the other node
                ble_rssi = pkt.get("ble_rssi_of_sender", -99)
                if ble_rssi > -99:
                    lnk = get_link(node_id, "BLE")
                    lnk["rssi"]      = ble_rssi
                    lnk["last_seen"] = recv_ts
                    lnk["power_cost"]= min(1.0, max(0.05, (-ble_rssi - 50) / 40.0))
                ping_pending.pop((node_id, "WiFi"), None)
                rebuild_routing_table()
                print(f"[PONG] {node_id} WiFi RTT={rtt_ms:.1f}ms  BLE_RSSI={ble_rssi}dBm")

            elif ptype == "METRIC":
                # Relay towards gateway (mesh forwarding)
                hop = pkt.get("hop_count", 0) + 1
                if hop <= 10:
                    pkt["hop_count"]  = hop
                    pkt["relayed_by"] = NODE_ID
                    udp_send(GATEWAY_IP, UDP_GW_PORT, pkt)
                    print(f"[Relay] Forwarded METRIC from {node_id} hop={hop}")

    except OSError:
        pass  # No data available – normal for non-blocking socket


# ══════════════════════════════════════════════
#  PROCESS BLE RECEIVE BUFFER
# ══════════════════════════════════════════════

# Print BLE messages only every Nth packet per node to reduce spam
# e.g. BLE_PRINT_EVERY = 10 means 1 print per ~1 second (BLE fires ~10x/sec)
BLE_PRINT_EVERY = 10
_ble_recv_count = {}   # { node_id: count }

def process_ble_buffer():
    while ble_rx_buffer:
        decoded  = ble_rx_buffer.pop(0)
        node_id  = decoded.get("node_id", "")
        pkt_type = decoded.get("pkt_type")
        adv_rssi = decoded.get("adv_rssi", -99)
        lat_ms   = decoded.get("lat_ms", 0.0)
        loss     = decoded.get("loss", 0.0)
        now      = time.time()

        lnk = get_link(node_id, "BLE")
        lnk["rssi"]      = adv_rssi
        lnk["last_seen"] = now
        lnk["power_cost"]= min(1.0, max(0.05, (-adv_rssi - 50) / 40.0))

        if pkt_type in (BLE_PKT_TYPE_HELLO, BLE_PKT_TYPE_METRIC):
            if lat_ms > 0:
                lnk["latency_samples"].append(lat_ms)
                if len(lnk["latency_samples"]) > 10:
                    lnk["latency_samples"].pop(0)
            if pkt_type == BLE_PKT_TYPE_METRIC:
                lnk["recv_count"] += 1
                lnk["packet_loss"] = loss

                # ── BLE-to-WiFi relay ──────────────────────────────────
                # If WE have WiFi and the sender only has BLE (no WiFi
                # link seen for them), forward a metric packet to the
                # gateway on their behalf so they appear in the Health Matrix.
                sender_has_wifi = get_link(node_id, "WiFi")["last_seen"] > 0
                if wifi_active and not sender_has_wifi:
                    relay_pkt = {
                        "type"        : "METRIC",
                        "node_id"     : node_id,       # original sender's ID
                        "protocol"    : "BLE",          # flag as BLE-sourced
                        "timestamp"   : now,
                        "seq_number"  : decoded.get("seq_hop", 0),
                        "hop_count"   : 1,
                        "rssi"        : adv_rssi,       # BLE RSSI we measured
                        "ip"          : "BLE-only",
                        "relayed_by"  : NODE_ID,        # us
                        "neighbours"  : [NODE_ID],
                        "routing_table": {},
                        "metrics": {
                            "wifi_avg_latency_ms": 0,
                            "ble_avg_latency_ms" : lat_ms,
                            "wifi_packet_loss"   : 1.0,   # no WiFi = 100% WiFi loss
                            "ble_packet_loss"    : loss,
                            "wifi_rssi"          : -99,
                            "ble_rssi"           : adv_rssi,
                        }
                    }
                    ok = udp_send(GATEWAY_IP, UDP_GW_PORT, relay_pkt)
                    if ok:
                        print(f"[Relay] BLE→WiFi: forwarded {node_id} metric to gateway")

            rebuild_routing_table()
            # Throttle: only print every BLE_PRINT_EVERY messages per node
            _ble_recv_count[node_id] = _ble_recv_count.get(node_id, 0) + 1
            if _ble_recv_count[node_id] % BLE_PRINT_EVERY == 1:
                label = "Hello" if pkt_type == BLE_PKT_TYPE_HELLO else "Metric"
                print(f"[BLE]  {label} from {node_id}  RSSI={adv_rssi}dBm  (#{_ble_recv_count[node_id]})")

        elif pkt_type == BLE_PKT_TYPE_PING:
            # Sender pinged via BLE adv – respond via WiFi with BLE RSSI included
            wifi_ip = get_link(node_id, "WiFi").get("ip")
            if wifi_ip:
                pong = {
                    "type"              : "PONG",
                    "node_id"           : NODE_ID,
                    "protocol"          : "BLE_via_WiFi",
                    "ping_ts"           : decoded.get("ts"),
                    "timestamp"         : now,
                    "ble_rssi_of_sender": adv_rssi
                }
                udp_send(wifi_ip, UDP_MESH_PORT, pong)


# ══════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════

def main():
    global last_hello_time, last_metric_time, last_ping_time
    global wifi_active, ble_active, my_ip, udp_sock

    print("╔══════════════════════════════════════════╗")
    print(f"║  Mesh Node  {NODE_ID:<8}  (Pico W)      ║")
    print("║  Dual-Protocol: WiFi + BLE               ║")
    print("╚══════════════════════════════════════════╝")

    # ── Try WiFi (non-fatal if it fails) ────────────────────────
    connect_wifi()
    if wifi_active:
        setup_udp()
    else:
        print("[Node] WiFi unavailable – starting in BLE-only mode")

    # ── Start BLE (non-fatal if it fails) ───────────────────────
    setup_ble()

    if not wifi_active and not ble_active:
        print("[FATAL] Both WiFi and BLE unavailable. Cannot start.")
        return

    # ── Report active protocols ──────────────────────────────────
    active = []
    if wifi_active: active.append(f"WiFi ({my_ip})")
    if ble_active:  active.append("BLE")
    print(f"\n[Node] {NODE_ID} ready  –  Active: {' + '.join(active)}\n")

    last_hello_time   = 0
    last_metric_time  = 0
    last_ping_time    = 0
    last_wifi_retry   = 0
    last_wifi_check   = 0
    WIFI_RETRY_INTERVAL = 60   # trigger a new reconnect attempt every 60s
    WIFI_CHECK_INTERVAL = 5    # check if background connect succeeded every 5s

    while True:
        now = time.time()

        # ── WiFi background reconnect logic ──────────────────────
        if not wifi_active:
            # Every 5s: check if the background connect attempt succeeded
            if now - last_wifi_check >= WIFI_CHECK_INTERVAL:
                if wlan and wlan.isconnected():
                    my_ip = wlan.ifconfig()[0]
                    wifi_active = True
                    if udp_sock is None:
                        setup_udp()
                    print(f"[WiFi] Connected  IP={my_ip}")
                last_wifi_check = now

            # Every 60s: trigger a fresh reconnect attempt (non-blocking)
            if now - last_wifi_retry >= WIFI_RETRY_INTERVAL:
                check_wifi_reconnect()
                last_wifi_retry = now

        # A. Neighbour Discovery (Hello over WiFi + BLE)
        if now - last_hello_time >= HELLO_INTERVAL:
            broadcast_hello()
            prune_stale_routes()
            last_hello_time = now

        # B. RTT Probes (Ping over WiFi, BLE beacon)
        if now - last_ping_time >= PING_INTERVAL:
            ping_all_neighbours()
            last_ping_time = now

        # C. Send metric packets (WiFi UDP + BLE advertisement)
        if now - last_metric_time >= METRIC_INTERVAL:
            send_metrics()
            last_metric_time = now

        # D. Receive and process incoming WiFi packets (skipped if no WiFi)
        if wifi_active and udp_sock is not None:
            process_wifi_packets()

        # E. Process BLE scan results from IRQ buffer (skipped if no BLE)
        if ble_active:
            process_ble_buffer()

        time.sleep(0.05)


# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════
if __name__ == "__main__":
    main()