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
from datetime import datetime
from collections import deque
from flask import Flask, jsonify

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
#  PACKET SEQUENCE TRACKER  (per node)
# ─────────────────────────────────────────────
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

    latency   = metrics.get("latency_avg", 0.0)
    loss      = metrics.get("packet_loss", 0.0)
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
    """Full health matrix server.py polls this."""
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


def run_flask():
    log.info(f"[Flask] REST API starting on port {FLASK_PORT}")
    flask_app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  IoT Mesh Gateway  –  Raspberry Pi 4")
    print("=" * 60)
    log.info("Gateway starting...")

    threads = [
        threading.Thread(target=udp_metric_listener, daemon=True, name="MetricListener"),
        threading.Thread(target=udp_mesh_listener,   daemon=True, name="MeshListener"),
        threading.Thread(target=watchdog_loop,        daemon=True, name="Watchdog"),
        threading.Thread(target=persist_loop,         daemon=True, name="Persist"),
        threading.Thread(target=dashboard_loop,       daemon=True, name="Dashboard"),
        threading.Thread(target=run_flask,            daemon=True, name="Flask"),
    ]

    for t in threads:
        t.start()
        log.info(f"Thread started: {t.name}")

    log.info("Gateway fully operational. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Gateway shutting down.")

if __name__ == "__main__":
    main()