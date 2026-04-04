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
import logging
import copy
import hmac
import hashlib
from datetime import datetime
from flask import Flask, jsonify

SHARED_KEY = b"mesh_secret_2106"

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
NODE_TIMEOUT_SEC_BLE = 120

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG, 
    # level=logging.INFO,
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

def sign_packet(pkt_dict):
    """Add HMAC-SHA256 signature to outgoing packet."""
    payload = json.dumps(pkt_dict).encode()
    sig = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
    pkt_dict["sig"] = sig
    return pkt_dict

def verify_packet(pkt_dict):
    """Verify HMAC-SHA256 signature on incoming packet. Returns True if valid."""
    sig = pkt_dict.pop("sig", None)
    if not sig:
        return False
    payload = json.dumps(pkt_dict).encode()
    expected = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
    return sig == expected

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

    # Use wifi_avg_latency_ms (the actual key node.py sends); fall back to ble if wifi absent
    latency   = metrics.get("wifi_avg_latency_ms", metrics.get("ble_avg_latency_ms", 0.0))
    # Use wifi_packet_loss (the actual key node.py sends); fall back to ble if wifi absent
    loss      = metrics.get("wifi_packet_loss",    metrics.get("ble_packet_loss",    0.0))
    throughput= metrics.get("throughput_est", 0.0)

    # Pull route preference fields if the node included them (sent in every METRIC)
    route_mode = pkt.get("route_mode", None)
    weights    = pkt.get("weights",    None)

    with matrix_lock:
        existing = health_matrix.get(node_id, {})

        # ── Sequence number tracking ───────────────────────────────
        if node_id not in seq_tracker:
            seq_tracker[node_id] = {"last_seq": seq, "expected_seq": seq + 1,
                                     "total_received": 1, "total_lost": 0}
        else:
            st     = seq_tracker[node_id]
            gap    = seq - st["last_seq"] - 1
            # Only count positive gaps as losses; negative means out-of-order
            # delivery or seq wrap-around — don't subtract from total_lost.
            if gap > 0:
                st["total_lost"] += gap
                log.warning(f"[{node_id}] Detected {gap} lost packet(s) (seq {st['last_seq']+1}–{seq-1})")
            elif gap < -1:
                log.debug(f"[{node_id}] Out-of-order or wrapped seq: last={st['last_seq']} new={seq}")
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
            # Store full per-protocol metrics so server.py and frontend can
            # access wifi_rssi, ble_rssi, wifi_packet_loss, ble_packet_loss etc.
            "metrics"         : metrics,
            # Route preference — updated from METRIC packets and ROUTE_PREF_ACK
            "route_mode"      : route_mode or existing.get("route_mode", "balanced"),
            "route_weights"   : weights    or existing.get("route_weights", {}),
            "route_ack_time"  : existing.get("route_ack_time"),   # last time node ACK'd a pref change
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
                "avg_latency_ms" : 0.0,
                "packet_loss"    : 0.0,
                "routing_table": rt,
                "sender_ip"  : sender_ip,
                "alerts"     : [],
                "packets_received": 0,
                "packets_lost": 0,
                # Initialise metrics dict so downstream code never gets KeyError
                "metrics"    : {},
            }
            log.info(f"[Hello] New node discovered: {node_id} @ {sender_ip}")
        else:
            health_matrix[node_id]["last_seen"]     = now
            health_matrix[node_id]["last_seen_str"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            health_matrix[node_id]["rssi"]          = rssi
            health_matrix[node_id]["routing_table"] = rt
            # Keep protocol and sender_ip current in case node switched WiFi↔BLE
            health_matrix[node_id]["protocol"]      = pkt.get("protocol", health_matrix[node_id].get("protocol", "WiFi"))
            health_matrix[node_id]["sender_ip"]     = sender_ip


# ─────────────────────────────────────────────
#  PROCESS ROUTE_PREF_ACK  (node confirmed weight update)
# ─────────────────────────────────────────────
def process_route_pref_ack(pkt, sender_ip):
    """
    Node sends ROUTE_PREF_ACK after applying new routing weights.
    Store the confirmed mode + weights so the dashboard can show live status.
    """
    node_id = pkt.get("node_id")
    if not node_id:
        return
    mode    = pkt.get("mode", "balanced")
    weights = {
        "w_latency"     : pkt.get("w_latency"),
        "w_packet_loss" : pkt.get("w_packet_loss"),
        "w_power"       : pkt.get("w_power"),
    }
    now = time.time()
    with matrix_lock:
        if node_id in health_matrix:
            health_matrix[node_id]["route_mode"]     = mode
            health_matrix[node_id]["route_weights"]  = weights
            health_matrix[node_id]["route_ack_time"] = now
            health_matrix[node_id]["sender_ip"]      = sender_ip   # refresh IP from ACK
    log.info(f"[RoutePref] ACK from {node_id}: mode={mode} "
             f"L={weights['w_latency']} P={weights['w_packet_loss']} W={weights['w_power']}")


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
                proto    = data.get("protocol", "WiFi")
                is_ble   = ("BLE" in proto and
                            data.get("sender_ip") in
                            ("BLE-direct", "BLE-only", ""))
                timeout  = NODE_TIMEOUT_SEC_BLE if is_ble else NODE_TIMEOUT_SEC
                if age > timeout and data.get("status") != "OFFLINE":
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
            # Deep-copy inside the lock so json.dump (which runs outside
            # the lock) serialises a stable snapshot.  dict(health_matrix)
            # is only a shallow copy — node sub-dicts (e.g. latency_history)
            # would still be shared references and could be mutated mid-dump.
            snapshot = {
                "gateway_timestamp": time.time(),
                "gateway_time_str" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "node_count"       : len(health_matrix),
                "nodes"            : copy.deepcopy(health_matrix)
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

    while True:
        try:
            raw, addr = sock.recvfrom(4096)  # keep raw bytes
            sender_ip = addr[0]

            if not verify_packet_raw(raw):   # verify BEFORE parsing
                log.warning(f"[Security] Rejected invalid packet from {sender_ip}")
                continue

            pkt   = json.loads(raw.decode('utf-8'))
            pkt.pop("sig", None)             # strip sig before processing
            ptype = pkt.get("type")
            if ptype == "METRIC":
                process_metric_packet(pkt, sender_ip)
            elif ptype == "HELLO":
                process_hello_packet(pkt, sender_ip)
        except json.JSONDecodeError:
            log.warning(f"[UDP] Malformed JSON from {addr}")
        except Exception as e:
            log.error(f"[UDP] Metric listener error: {e}")
            
def verify_packet_raw(raw_bytes):
    try:
        pkt = json.loads(raw_bytes.decode('utf-8'))
        sig = pkt.pop("sig", None)
        if not sig:
            log.warning("[Security] Packet missing 'sig' field entirely")
            return False

        payload  = json.dumps(pkt, sort_keys=True, separators=(',', ':')).encode()
        expected = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()

        # ── Debug: log first 20 chars of each sig so you can spot the mismatch ──
        log.debug(f"[Security] sig_received : {sig[:20]}...")
        log.debug(f"[Security] sig_expected : {expected[:20]}...")
        log.debug(f"[Security] payload_preview: {payload[:80]}")

        match = hmac.compare_digest(sig, expected)
        if not match:
            log.warning(f"[Security] HMAC mismatch — received={sig[:20]}... expected={expected[:20]}...")
            log.warning(f"[Security] Payload used for verify: {payload[:120]}")
        return match
    except Exception as e:
        log.warning(f"[Security] verify_packet_raw exception: {e}")
        return False

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
            raw, addr = sock.recvfrom(4096)
            sender_ip = addr[0]

            if not verify_packet_raw(raw):        # ← was verify_packet, now consistent
                log.warning(f"[Security] Rejected invalid packet from {sender_ip}")
                continue

            pkt = json.loads(raw.decode('utf-8'))
            pkt.pop("sig", None)
            ptype = pkt.get("type")
            if ptype == "HELLO":
                process_hello_packet(pkt, sender_ip)
            elif ptype == "ROUTE_PREF_ACK":
                process_route_pref_ack(pkt, sender_ip)
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
        # Deep-copy inside lock so Flask/jsonify serialises a stable snapshot
        data = {
            "gateway_timestamp": time.time(),
            "gateway_time_str" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "node_count"       : len(health_matrix),
            "nodes"            : copy.deepcopy(health_matrix)
        }
    return jsonify(data)


@flask_app.route("/node/<node_id>", methods=["GET"])
def api_node(node_id):
    """Single node details."""
    with matrix_lock:
        node = health_matrix.get(node_id)
        # Copy inside the lock so jsonify serialises a stable snapshot,
        # not a live dict that another thread may mutate mid-serialise.
        node_copy = copy.deepcopy(node) if node else None
    if node_copy:
        return jsonify(node_copy)
    return jsonify({"error": "Node not found"}), 404

@flask_app.route("/route_pref", methods=["POST"])
def api_route_pref():
    """Receive weight update from server.py and forward to node via UDP."""
    data = request.get_json()
    node_id  = data.get("node_id")
    mode     = data.get("mode", "balanced")
    weights  = data.get("weights", {})

    with matrix_lock:
        node = health_matrix.get(node_id)
    if not node:
        return jsonify({"ok": False, "error": f"{node_id} not in health matrix"}), 404

    sender_ip = node.get("sender_ip", "")
    if not sender_ip or sender_ip in ("BLE-direct", "BLE-only", ""):
        return jsonify({"ok": False, "error": "BLE-only node — no WiFi IP"}), 400

    cmd = {
        "type":          "ROUTE_PREF",
        "node_id":       "GATEWAY",
        "target":        node_id,
        "mode":          mode,
        "w_latency":     weights.get("w_latency", 0.5),
        "w_packet_loss": weights.get("w_packet_loss", 0.3),
        "w_power":       weights.get("w_power", 0.2),
        "timestamp":     int(time.time()),
    }
    sign_packet(cmd)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.sendto(json.dumps(cmd).encode(), (sender_ip, 5005))
        s.close()
        log.info(f"[RoutePref] Forwarded {mode} to {node_id} @ {sender_ip}")
        return jsonify({"ok": True, "message": f"Sent to {node_id} @ {sender_ip}"})
    except Exception as e:
        log.error(f"[RoutePref] Failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


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
                    "latency"  : route.get("avg_latency_ms"),   # key is avg_latency_ms not avg_latency
                    "cost"     : route.get("cost"),
                    "protocol" : route.get("best_protocol"),    # pass protocol so topology can colour edges
                })
    return jsonify({"edges": edges})


@flask_app.route("/ping", methods=["GET"])
def api_ping():
    return jsonify({"status": "ok", "gateway": "running"})


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
            if len(full) >= 2 and full[0:2] == bytes([0xAA, 0xBB]):
                log.debug(f"[BLE-GW] Mesh-magic packet from {device.address} "
                         f"len={len(full)} company_id=0x{company_id:04X}")
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
            lat_ms   = decoded["lat_ms"]

            # Estimate latency from RSSI if node sent 0
            if lat_ms == 0.0 and adv_rssi > -99:
                lat_ms = max(20.0, min(120.0, (adv_rssi + 40) * -1.375 + 25))

            # Dedup: only fully process new seq numbers
            last_seq = _ble_last_seq.get(node_id)
            is_new   = (last_seq is None or last_seq != seq)
            if is_new:
                _ble_last_seq[node_id] = seq

            # ALWAYS update last_seen and rssi even for duplicate seq
            # This prevents watchdog timeout between seq changes
            with matrix_lock:
                if node_id in health_matrix:
                    health_matrix[node_id]["last_seen"] = now
                    health_matrix[node_id]["last_seen_str"] = \
                        datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
                    health_matrix[node_id]["rssi"] = adv_rssi
                    if health_matrix[node_id].get("status") == "OFFLINE":
                        # Node came back online
                        health_matrix[node_id]["status"] = "ONLINE"
                        health_matrix[node_id]["health_score"] = 100.0
                        health_matrix[node_id]["alerts"] = []
                        log.info(f"[BLE-GW] {node_id} back ONLINE")

            if pkt_type == BLE_PKT_TYPE_METRIC and is_new:
                pkt = {
                    "type"         : "METRIC",
                    "node_id"      : node_id,
                    "protocol"     : "BLE-Direct",
                    "timestamp"    : now,
                    "seq_number"   : seq,
                    "hop_count"    : 0,
                    "rssi"         : adv_rssi,
                    "ip"           : "BLE-only",
                    "neighbours"   : [],
                    "routing_table": {},
                    "metrics": {
                        "wifi_avg_latency_ms": 0,
                        "ble_avg_latency_ms" : lat_ms,
                        "wifi_packet_loss"   : 1.0,
                        "ble_packet_loss"    : decoded["loss"],
                        "wifi_rssi"          : -99,
                        "ble_rssi"           : adv_rssi,
                        "wifi_power_cost"    : 1.0,
                        "ble_power_cost"     : min(1.0, max(0.05,
                                                  (-adv_rssi - 50) / 40.0)),
                    },
                }
                process_metric_packet(pkt, "BLE-direct")
                log.info(f"[BLE-GW] Direct metric from {node_id}  "
                         f"RSSI={adv_rssi}dBm  lat={lat_ms:.1f}ms  seq={seq}")

            elif pkt_type == BLE_PKT_TYPE_HELLO and is_new:
                # Use process_hello_packet to create entry if not exists
                process_hello_packet({
                    "type"    : "HELLO",
                    "node_id" : node_id,
                    "protocol": "BLE-Direct",
                    "rssi"    : adv_rssi,
                    "routing" : {},
                }, "BLE-direct")
                log.debug(f"[BLE-GW] Hello from {node_id}  "
                          f"RSSI={adv_rssi}dBm  seq={seq}")

    except Exception as e:
        log.debug(f"[BLE-GW] Callback error: {e}")


async def ble_scan_async():
    """Async BLE scanner loop – runs forever, auto-restarts on error."""
    log.info("[BLE-GW] Starting BLE scanner on Raspberry Pi Bluetooth...")
    while True:
        try:
            scanner = BleakScanner(detection_callback=ble_advertisement_callback)
            await scanner.start()
            log.info("[BLE-GW] ✅ BLE scanner active – listening for node beacons")
            while True:
                await asyncio.sleep(1)
        except Exception as e:
            log.error(f"[BLE-GW] Scanner error: {e}")
            log.error("[BLE-GW] Restarting BLE scanner in 5 seconds...")
            await asyncio.sleep(5)


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

def rssi_to_ble_latency(rssi):
    """Estimate BLE latency from RSSI when no samples available."""
    if rssi <= -99:
        return 0.0
    # -40 dBm (strong) → ~25ms, -80 dBm (weak) → ~80ms
    return max(20.0, min(120.0, (rssi + 40) * -1.375 + 25))


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