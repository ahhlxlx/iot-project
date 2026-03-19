"""
===================================================
IoT Mesh Network Gateway - Raspberry Pi 4
===================================================
Responsibilities:
  - Host a WiFi Access Point (hostapd) OR connect
    to a shared router that all Pico W nodes join
  - Listen on UDP port 5006 for incoming metric packets
  - Listen on UDP port 5005 to participate in Hello
    broadcasts (optional: gateway can also advertise)
  - Parse and validate all incoming packets
  - Maintain a live Health Matrix per node
  - Expose the Health Matrix to server.py via:
      * A local JSON file  (health_matrix.json)
      * A simple REST API  (Flask on port 8080)
  - Print a live terminal dashboard for debugging
===================================================
Requirements:
    pip install flask
    Python 3.9+
===================================================
"""

import socket
import threading
import json
import time
import os
import math
import logging
import struct
from datetime import datetime
from collections import deque
from flask import Flask, jsonify

# BLE scanner – uses bluezdbus (bleak) on the Raspberry Pi
# Install with: pip install bleak
BLE_SCAN_ENABLED = True   # set False if you don't have bleak installed
try:
    import asyncio
    from bleak import BleakScanner
except ImportError:
    BLE_SCAN_ENABLED = False
    print("[BLE-GW] bleak not installed – BLE scanning disabled")
    print("[BLE-GW] Install with: pip install bleak")

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
GATEWAY_LISTEN_IP   = "0.0.0.0"
GATEWAY_PORT        = 5006          # Port that nodes send metrics to
MESH_PORT           = 5005          # Port for Hello / mesh broadcast participation
HEALTH_MATRIX_FILE  = "health_matrix.json"
FLASK_PORT          = 8080          # REST API port for server.py
LOG_FILE            = "gateway.log"

# Health thresholds (used to compute node health score)
LATENCY_WARN_MS     = 100           # ms
LATENCY_CRIT_MS     = 300           # ms
PACKET_LOSS_WARN    = 0.05          # 5%
PACKET_LOSS_CRIT    = 0.20          # 20%
RSSI_WARN_DBM       = -75
RSSI_CRIT_DBM       = -85
NODE_TIMEOUT_SEC    = 60            # Mark node OFFLINE if no packet for this long

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("gateway")

# ─────────────────────────────────────────────
#  HEALTH MATRIX  (shared state, thread-safe via lock)
# ─────────────────────────────────────────────
matrix_lock   = threading.Lock()
health_matrix = {}
"""
health_matrix structure:
{
  "NODE_01": {
    "node_id"        : str,
    "protocol"       : str,
    "status"         : "ONLINE" | "OFFLINE" | "DEGRADED",
    "health_score"   : float,        # 0-100
    "last_seen"      : float,        # Unix timestamp
    "last_seen_str"  : str,
    "rssi"           : int,          # dBm
    "avg_latency_ms" : float,
    "packet_loss"    : float,        # 0.0 – 1.0
    "throughput_est" : float,        # kbps estimate
    "hop_count"      : int,
    "seq_last"       : int,
    "seq_expected"   : int,
    "packets_received": int,
    "packets_lost"   : int,
    "neighbours"     : list[str],
    "routing_table"  : dict,
    "latency_history": list[float],  # last 20 samples
    "rssi_history"   : list[int],    # last 20 samples
    "alerts"         : list[str]
  },
  ...
}
"""

# ─────────────────────────────────────────────
#  BLE PACKET DECODER
#  Must match encode_ble() in node.py exactly
#  Layout: 2B magic | 1B type | 7B node_id | 1B seq |
#          4B timestamp | 1B rssi | 2B latency | 1B loss
# ─────────────────────────────────────────────
BLE_MAGIC           = bytes([0xAA, 0xBB])
BLE_PKT_TYPE_HELLO  = 0x01
BLE_PKT_TYPE_METRIC = 0x02
BLE_PKT_TYPE_PING   = 0x03
BLE_PKT_TYPE_PONG   = 0x04

def decode_ble_payload(manuf_data):
    """Decode manufacturer-specific BLE advertisement from a mesh node."""
    try:
        b = bytes(manuf_data)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None
        node_id = b[3:10].rstrip(b'\x00').decode('utf-8')
        if not node_id or not node_id.startswith("NODE_") or len(node_id) > 7:
            return None
        return {
            "pkt_type": b[2],
            "node_id" : node_id,
            "seq"     : b[10],
            "ts"      : int.from_bytes(b[11:15], 'big'),
            "rssi"    : b[15] - 128,
            "lat_ms"  : ((b[16] << 8) | b[17]) / 10.0,
            "loss"    : b[18] / 255.0
        }
    except Exception:
        return None


def find_manuf_data_gw(adv_data_bytes):
    """Extract manufacturer-specific (type 0xFF) data from raw BLE adv bytes."""
    b   = bytes(adv_data_bytes)
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
seq_tracker = {}   # { node_id: { last_seq, expected_seq } }

# ─────────────────────────────────────────────
#  HEALTH SCORE CALCULATOR
# ─────────────────────────────────────────────
def compute_health_score(node_data):
    """
    Returns a 0-100 health score and a list of alert strings.
    100 = perfect, 0 = completely failed.
    """
    score  = 100.0
    alerts = []

    latency = node_data.get("avg_latency_ms", 0)
    if latency >= LATENCY_CRIT_MS:
        score -= 30
        alerts.append(f"CRITICAL latency: {latency:.1f} ms")
    elif latency >= LATENCY_WARN_MS:
        score -= 15
        alerts.append(f"HIGH latency: {latency:.1f} ms")

    loss = node_data.get("packet_loss", 0.0)
    if loss >= PACKET_LOSS_CRIT:
        score -= 30
        alerts.append(f"CRITICAL packet loss: {loss*100:.1f}%")
    elif loss >= PACKET_LOSS_WARN:
        score -= 15
        alerts.append(f"HIGH packet loss: {loss*100:.1f}%")

    rssi = node_data.get("rssi", -99)
    if rssi <= RSSI_CRIT_DBM:
        score -= 20
        alerts.append(f"CRITICAL signal: {rssi} dBm")
    elif rssi <= RSSI_WARN_DBM:
        score -= 10
        alerts.append(f"WEAK signal: {rssi} dBm")

    hops = node_data.get("hop_count", 0)
    if hops > 3:
        score -= (hops - 3) * 5
        alerts.append(f"High hop count: {hops}")

    status = "ONLINE"
    if score < 40:
        status = "DEGRADED"
    if score <= 0 or node_data.get("status") == "OFFLINE":
        status = "OFFLINE"
        score  = 0

    return max(0.0, round(score, 1)), status, alerts


# ─────────────────────────────────────────────
#  PROCESS INCOMING METRIC PACKET
# ─────────────────────────────────────────────
def process_metric_packet(pkt, sender_ip):
    node_id  = pkt.get("node_id")
    if not node_id:
        return

    now      = time.time()
    now_str  = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    metrics  = pkt.get("metrics", {})
    seq      = pkt.get("seq_number", 0)
    rt       = pkt.get("routing_table", {})
    nb       = pkt.get("neighbours", [])
    rssi     = pkt.get("rssi", -99)
    hops     = pkt.get("hop_count", 0)
    protocol = pkt.get("protocol", "WiFi")

    # Extract latency from per-protocol metrics (node sends wifi_avg_latency_ms / ble_avg_latency_ms)
    wifi_lat = metrics.get("wifi_avg_latency_ms", 0.0)
    ble_lat  = metrics.get("ble_avg_latency_ms", 0.0)
    # Use whichever is available; prefer WiFi if both present
    if wifi_lat > 0 and ble_lat > 0:
        latency = min(wifi_lat, ble_lat)
    elif wifi_lat > 0:
        latency = wifi_lat
    elif ble_lat > 0:
        latency = ble_lat
    else:
        latency = metrics.get("latency_avg", 0.0)

    wifi_loss = metrics.get("wifi_packet_loss", 0.0)
    ble_loss  = metrics.get("ble_packet_loss", 0.0)
    loss      = min(wifi_loss, ble_loss) if (wifi_loss < 1.0 and ble_loss < 1.0) else max(0, min(wifi_loss, ble_loss))
    if loss == 0 and (wifi_loss > 0 or ble_loss > 0):
        loss = wifi_loss if wifi_loss > 0 else ble_loss
    throughput= metrics.get("throughput_est", 0.0)

    with matrix_lock:
        existing = health_matrix.get(node_id, {})

        # ── Sequence number tracking ───────────────────────────────
        if node_id not in seq_tracker:
            seq_tracker[node_id] = {"last_seq": seq, "expected_seq": seq + 1,
                                     "total_received": 1, "total_lost": 0}
        else:
            st     = seq_tracker[node_id]
            gap    = seq - st["last_seq"] - 1
            if gap > 0:
                st["total_lost"] += gap
                log.warning(f"[{node_id}] Detected {gap} lost packet(s) (seq {st['last_seq']+1}–{seq-1})")
            st["total_received"] += 1
            st["last_seq"]        = seq
            st["expected_seq"]    = seq + 1

        st          = seq_tracker[node_id]
        total_rx    = st["total_received"]
        total_lost  = st["total_lost"]
        real_loss   = total_lost / (total_rx + total_lost) if (total_rx + total_lost) > 0 else 0.0

        # ── Rolling histories ───────────────────────────────────────
        lat_hist  = existing.get("latency_history", [])
        rssi_hist = existing.get("rssi_history", [])
        lat_hist.append(latency)
        rssi_hist.append(rssi)
        if len(lat_hist)  > 20: lat_hist.pop(0)
        if len(rssi_hist) > 20: rssi_hist.pop(0)

        # ── Build updated node entry ────────────────────────────────
        node_data = {
            "node_id"         : node_id,
            "protocol"        : protocol,
            "sender_ip"       : sender_ip,
            "last_seen"       : now,
            "last_seen_str"   : now_str,
            "rssi"            : rssi,
            "avg_latency_ms"  : latency,
            "packet_loss"     : round(real_loss, 4),
            "throughput_est"  : throughput,
            "hop_count"       : hops,
            "seq_last"        : seq,
            "seq_expected"    : seq + 1,
            "packets_received": total_rx,
            "packets_lost"    : total_lost,
            "neighbours"      : nb,
            "routing_table"   : rt,
            "latency_history" : lat_hist,
            "rssi_history"    : rssi_hist,
            "metrics"         : metrics,  # full per-protocol metrics for dashboard
            "route_mode"      : pkt.get("route_mode", "balanced"),
            "weights"         : pkt.get("weights", {"w_latency": 0.5, "w_packet_loss": 0.3, "w_power": 0.2}),
        }

        score, status, alerts = compute_health_score(node_data)
        node_data["health_score"]   = score
        node_data["status"]         = status
        node_data["alerts"]         = alerts

        health_matrix[node_id] = node_data

    log.info(
        f"[{node_id}] Protocol={protocol} Seq={seq} RSSI={rssi}dBm "
        f"Latency={latency:.1f}ms Loss={real_loss*100:.1f}% "
        f"Hops={hops} Score={score} Status={status}"
    )


# ─────────────────────────────────────────────
#  PROCESS HELLO PACKET (optional – gateway learns topology)
# ─────────────────────────────────────────────
def process_hello_packet(pkt, sender_ip):
    node_id = pkt.get("node_id")
    if not node_id:
        return
    now     = time.time()
    rssi    = pkt.get("rssi", -99)
    rt      = pkt.get("routing", {})

    with matrix_lock:
        if node_id not in health_matrix:
            health_matrix[node_id] = {
                "node_id"    : node_id,
                "protocol"   : pkt.get("protocol", "WiFi"),
                "status"     : "ONLINE",
                "health_score": 100.0,
                "last_seen"  : now,
                "last_seen_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                "rssi"       : rssi,
                "routing_table": rt,
                "sender_ip"  : sender_ip,
                "alerts"     : [],
                "packets_received": 0,
                "packets_lost": 0
            }
            log.info(f"[Hello] New node discovered: {node_id} @ {sender_ip}")
        else:
            health_matrix[node_id]["last_seen"]     = now
            health_matrix[node_id]["last_seen_str"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            health_matrix[node_id]["rssi"]          = rssi
            health_matrix[node_id]["routing_table"] = rt


# ─────────────────────────────────────────────
#  MARK OFFLINE NODES
# ─────────────────────────────────────────────
def watchdog_loop():
    """Background thread – marks nodes OFFLINE if they stop sending."""
    while True:
        now = time.time()
        with matrix_lock:
            for node_id, data in health_matrix.items():
                age = now - data.get("last_seen", now)
                if age > NODE_TIMEOUT_SEC and data.get("status") != "OFFLINE":
                    health_matrix[node_id]["status"]       = "OFFLINE"
                    health_matrix[node_id]["health_score"] = 0
                    health_matrix[node_id]["alerts"]       = [f"Node silent for {int(age)}s"]
                    log.warning(f"[Watchdog] {node_id} marked OFFLINE (silent {int(age)}s)")
        time.sleep(10)


# ─────────────────────────────────────────────
#  PERSIST HEALTH MATRIX TO FILE
# ─────────────────────────────────────────────
def persist_loop():
    """Write health_matrix.json every 5 seconds for server.py to read."""
    while True:
        with matrix_lock:
            snapshot = {
                "gateway_timestamp": time.time(),
                "gateway_time_str" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "node_count"       : len(health_matrix),
                "nodes"            : dict(health_matrix)
            }
        with open(HEALTH_MATRIX_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
        time.sleep(5)


# ─────────────────────────────────────────────
#  TERMINAL DASHBOARD  (prints to stdout)
# ─────────────────────────────────────────────
def print_dashboard():
    os.system('clear' if os.name == 'posix' else 'cls')
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with matrix_lock:
        nodes = dict(health_matrix)

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║  IoT Mesh Gateway  │  {now_str}  │  Nodes: {len(nodes):<3}                     ║")
    print("╠══════════════════════════════════════════════════════════════════════════════╣")
    print(f"  {'Node ID':<12} {'Status':<10} {'Score':<7} {'RSSI':<8} {'Latency':<12} {'Loss':<8} {'Hops':<6} {'IP'}")
    print("  " + "─" * 76)

    for node_id, d in sorted(nodes.items()):
        status  = d.get("status", "?")
        score   = d.get("health_score", 0)
        rssi    = d.get("rssi", -99)
        lat     = d.get("avg_latency_ms", 0)
        loss    = d.get("packet_loss", 0) * 100
        hops    = d.get("hop_count", 0)
        ip      = d.get("sender_ip", "N/A")

        status_icon = {"ONLINE": "✅", "DEGRADED": "⚠️ ", "OFFLINE": "❌"}.get(status, "?")
        score_bar   = ("█" * int(score // 10)).ljust(10)
        print(f"  {node_id:<12} {status_icon} {status:<8} [{score_bar}] {score:<4} "
              f"{rssi:<8} {lat:<12.1f} {loss:<7.1f}% {hops:<6} {ip}")

        for alert in d.get("alerts", []):
            print(f"    ⚡  {alert}")

    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"  [REST API] http://localhost:{FLASK_PORT}/health_matrix")
    print(f"  [JSON File] {os.path.abspath(HEALTH_MATRIX_FILE)}")


def dashboard_loop():
    while True:
        print_dashboard()
        time.sleep(5)


# ─────────────────────────────────────────────
#  UDP LISTENER – GATEWAY PORT (metrics)
# ─────────────────────────────────────────────
def udp_metric_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((GATEWAY_LISTEN_IP, GATEWAY_PORT))
    log.info(f"[UDP] Metric listener on port {GATEWAY_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            sender_ip  = addr[0]
            pkt        = json.loads(data.decode('utf-8'))
            ptype      = pkt.get("type")
            if ptype == "METRIC":
                process_metric_packet(pkt, sender_ip)
            elif ptype == "HELLO":
                process_hello_packet(pkt, sender_ip)
        except json.JSONDecodeError:
            log.warning(f"[UDP] Malformed JSON from {addr}")
        except Exception as e:
            log.error(f"[UDP] Metric listener error: {e}")


# ─────────────────────────────────────────────
#  UDP LISTENER – MESH PORT (hello broadcast)
# ─────────────────────────────────────────────
def udp_mesh_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((GATEWAY_LISTEN_IP, MESH_PORT))
    log.info(f"[UDP] Mesh Hello listener on port {MESH_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            pkt        = json.loads(data.decode('utf-8'))
            if pkt.get("type") == "HELLO":
                process_hello_packet(pkt, addr[0])
        except Exception as e:
            log.error(f"[UDP] Mesh listener error: {e}")


# ─────────────────────────────────────────────
#  FLASK REST API  (for server.py)
# ─────────────────────────────────────────────
flask_app = Flask(__name__)

@flask_app.route("/health_matrix", methods=["GET"])
def api_health_matrix():
    """Full health matrix – server.py polls this."""
    with matrix_lock:
        data = {
            "gateway_timestamp": time.time(),
            "gateway_time_str" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "node_count"       : len(health_matrix),
            "nodes"            : dict(health_matrix)
        }
    return jsonify(data)


@flask_app.route("/node/<node_id>", methods=["GET"])
def api_node(node_id):
    """Single node details."""
    with matrix_lock:
        node = health_matrix.get(node_id)
    if node:
        return jsonify(node)
    return jsonify({"error": "Node not found"}), 404


@flask_app.route("/summary", methods=["GET"])
def api_summary():
    """Lightweight summary for quick dashboard polling."""
    with matrix_lock:
        summary = {}
        for nid, d in health_matrix.items():
            summary[nid] = {
                "status"      : d.get("status"),
                "health_score": d.get("health_score"),
                "rssi"        : d.get("rssi"),
                "avg_latency" : d.get("avg_latency_ms"),
                "packet_loss" : d.get("packet_loss"),
                "last_seen"   : d.get("last_seen_str"),
            }
    return jsonify({
        "node_count": len(summary),
        "nodes"     : summary,
        "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@flask_app.route("/topology", methods=["GET"])
def api_topology():
    """Returns mesh topology as edges for visualisation."""
    edges = []
    with matrix_lock:
        for nid, d in health_matrix.items():
            for nb in d.get("neighbours", []):
                edges.append({"from": nid, "to": nb})
            for dest, route in d.get("routing_table", {}).items():
                edges.append({
                    "from"     : nid,
                    "to"       : dest,
                    "via"      : route.get("next_hop"),
                    "hop_count": route.get("hop_count"),
                    "latency"  : route.get("avg_latency"),
                    "cost"     : route.get("cost")
                })
    return jsonify({"edges": edges})


@flask_app.route("/ping", methods=["GET"])
def api_ping():
    return jsonify({"status": "ok", "gateway": "running"})


# ── Route Preference Storage & Forwarding ──────────
# Track current route preferences per node
route_preferences = {}   # { node_id: { "mode": "latency"|"cost"|"power"|"balanced", "weights": {...} } }

# Predefined weight profiles
WEIGHT_PROFILES = {
    "latency":  {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05},
    "cost":     {"w_latency": 0.3, "w_packet_loss": 0.5,  "w_power": 0.2},
    "power":    {"w_latency": 0.1, "w_packet_loss": 0.2,  "w_power": 0.7},
    "balanced": {"w_latency": 0.5, "w_packet_loss": 0.3,  "w_power": 0.2},
}


def send_route_pref_to_node(node_id, mode, weights):
    """Send a ROUTE_PREF UDP command to the node so it adjusts its cost weights."""
    with matrix_lock:
        node = health_matrix.get(node_id)
    if not node:
        return False, "Node not found in health matrix"

    sender_ip = node.get("sender_ip")
    if not sender_ip or sender_ip in ("BLE-direct", "BLE-only"):
        # BLE-only node — can't send UDP command directly.
        # Store preference; node will need to poll or we relay via BLE later.
        route_preferences[node_id] = {"mode": mode, "weights": weights}
        return True, "Stored (BLE-only node — cannot UDP directly)"

    cmd = {
        "type"      : "ROUTE_PREF",
        "node_id"   : "GATEWAY",
        "target"    : node_id,
        "mode"      : mode,
        "w_latency" : weights["w_latency"],
        "w_packet_loss": weights["w_packet_loss"],
        "w_power"   : weights["w_power"],
        "timestamp" : time.time(),
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(json.dumps(cmd).encode(), (sender_ip, 5005))
        s.close()
        route_preferences[node_id] = {"mode": mode, "weights": weights}
        log.info(f"[RoutePref] Sent {mode} weights to {node_id} @ {sender_ip}")
        return True, f"Sent to {node_id}"
    except Exception as e:
        log.error(f"[RoutePref] Failed to send to {node_id}: {e}")
        return False, str(e)


@flask_app.route("/route_pref", methods=["POST"])
def api_set_route_pref():
    """Set routing preference for a node: latency, cost, power, or balanced."""
    from flask import request
    data = request.get_json(force=True)
    node_id = data.get("node_id")
    mode    = data.get("mode", "balanced")

    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    if mode not in WEIGHT_PROFILES:
        return jsonify({"error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}), 400

    weights = WEIGHT_PROFILES[mode]
    ok, msg = send_route_pref_to_node(node_id, mode, weights)
    return jsonify({"ok": ok, "message": msg, "node_id": node_id, "mode": mode, "weights": weights})


@flask_app.route("/route_pref", methods=["GET"])
def api_get_route_prefs():
    """Get current route preferences for all nodes."""
    return jsonify(route_preferences)


def run_flask():
    log.info(f"[Flask] REST API starting on port {FLASK_PORT}")
    flask_app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False)


# ─────────────────────────────────────────────
#  BLE GATEWAY SCANNER
#  Runs on the Raspberry Pi's built-in Bluetooth.
#  Directly receives BLE beacons from nodes that
#  have no WiFi – giving them a path to the gateway.
# ─────────────────────────────────────────────

# Dedup tracker: only process/log a BLE packet when seq number changes
# { node_id: last_seq }
_ble_last_seq = {}

def ble_advertisement_callback(device, advertisement_data):
    """Called by BleakScanner for every BLE advertisement received."""
    try:
        manuf = advertisement_data.manufacturer_data
        if not manuf:
            return
        for company_id, payload in manuf.items():
            full = bytes([company_id & 0xFF, (company_id >> 8) & 0xFF]) + bytes(payload)
            decoded = decode_ble_payload(full)
            if decoded is None:
                decoded = decode_ble_payload(bytes(payload))
            if decoded is None:
                continue

            node_id  = decoded["node_id"]
            pkt_type = decoded["pkt_type"]
            adv_rssi = advertisement_data.rssi or -99
            now      = time.time()
            seq      = decoded["seq"]

            # ── Dedup: skip if same seq as last time we processed this node ──
            # BLE advertises the same packet ~10x/sec – only act on new seq numbers
            last_seq = _ble_last_seq.get(node_id)
            is_new   = (last_seq != seq)
            if is_new:
                _ble_last_seq[node_id] = seq

            if pkt_type == BLE_PKT_TYPE_METRIC:
                # Always update RSSI (it changes even for same seq)
                # but only fully process and log on new seq
                if is_new:
                    pkt = {
                        "type"        : "METRIC",
                        "node_id"     : node_id,
                        "protocol"    : "BLE-Direct",
                        "timestamp"   : now,
                        "seq_number"  : seq,
                        "hop_count"   : 0,
                        "rssi"        : adv_rssi,
                        "ip"          : "BLE-only",
                        "neighbours"  : [],
                        "routing_table": {},
                        "metrics": {
                            "wifi_avg_latency_ms": 0,
                            "ble_avg_latency_ms" : decoded["lat_ms"],
                            "wifi_packet_loss"   : 1.0,
                            "ble_packet_loss"    : decoded["loss"],
                            "wifi_rssi"          : -99,
                            "ble_rssi"           : adv_rssi,
                        }
                    }
                    process_metric_packet(pkt, "BLE-direct")
                    log.info(f"[BLE-GW] Direct metric from {node_id}  "
                             f"RSSI={adv_rssi}dBm  seq={seq}")

            elif pkt_type == BLE_PKT_TYPE_HELLO and is_new:
                process_hello_packet({
                    "type"    : "HELLO",
                    "node_id" : node_id,
                    "protocol": "BLE-Direct",
                    "rssi"    : adv_rssi,
                    "routing" : {}
                }, "BLE-direct")

    except Exception as e:
        log.debug(f"[BLE-GW] Callback error: {e}")


async def ble_scan_async():
    """Async BLE scanner loop – runs forever in its own event loop."""
    log.info("[BLE-GW] Starting BLE scanner on Raspberry Pi Bluetooth...")
    try:
        scanner = BleakScanner(detection_callback=ble_advertisement_callback)
        await scanner.start()
        log.info("[BLE-GW] ✅ BLE scanner active – listening for node beacons")
        while True:
            await asyncio.sleep(1)
    except Exception as e:
        log.error(f"[BLE-GW] Scanner error: {e}")
        log.error("[BLE-GW] Make sure Bluetooth is enabled: sudo systemctl start bluetooth")


def ble_gateway_scanner():
    """Thread entry point – runs the async BLE scanner in its own event loop."""
    if not BLE_SCAN_ENABLED:
        log.warning("[BLE-GW] Skipped – bleak not installed")
        return
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(ble_scan_async())
    except Exception as e:
        log.error(f"[BLE-GW] Fatal: {e}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  IoT Mesh Gateway  –  Raspberry Pi 4")
    print("=" * 60)
    log.info("Gateway starting...")

    threads = [
        threading.Thread(target=udp_metric_listener,  daemon=True, name="MetricListener"),
        threading.Thread(target=udp_mesh_listener,    daemon=True, name="MeshListener"),
        threading.Thread(target=watchdog_loop,         daemon=True, name="Watchdog"),
        threading.Thread(target=persist_loop,          daemon=True, name="Persist"),
        threading.Thread(target=dashboard_loop,        daemon=True, name="Dashboard"),
        threading.Thread(target=run_flask,             daemon=True, name="Flask"),
        threading.Thread(target=ble_gateway_scanner,   daemon=True, name="BLE-Scanner"),
    ]

    for t in threads:
        t.start()
        log.info(f"  ✅  Thread started: {t.name}")

    log.info("Gateway fully operational. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Gateway shutting down.")


if __name__ == "__main__":
    main()