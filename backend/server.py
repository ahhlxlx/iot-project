"""
backend/server.py
Flask REST API + WebSocket server for the IoT mesh network backend.

Endpoints
---------
POST /api/packets          — Gateway pushes a received packet here
GET  /api/packets          — Recent packet log (default last 50)
GET  /api/health           — Per-node health matrix
GET  /api/routes           — Best-route analysis per source node
GET  /api/latency/<node>   — Latency time-series for one node
GET  /api/stats            — Network-wide summary statistics
GET  /                     — Serve the live dashboard (dashboard.html)

WebSocket /ws/live         — Pushes new packets to connected browsers in real-time
"""

import json
import time
import os
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sock import Sock
import threading

import database as db
from health_matrix import compute_node_health, health_matrix_to_dict
from route_selection import analyse_routes, best_routes_to_dict
from dotenv import load_dotenv
load_dotenv()
# ─── App setup ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

app  = Flask(__name__, static_folder="static")
CORS(app)           # allow dashboard on different port during development
sock = Sock(app)

# Thread-safe set of active WebSocket clients
_ws_clients: set = set()
_ws_lock = threading.Lock()

# ─── DB init ──────────────────────────────────────────────────────────────────
db.init_db()
log.info("Database initialised at %s", db.DB_PATH)


# ─── WebSocket broadcast helper ───────────────────────────────────────────────

def _broadcast(payload: dict):
    """Push a JSON message to all connected WebSocket clients."""
    msg = json.dumps(payload)
    dead = set()
    with _ws_lock:
        clients = set(_ws_clients)
    for ws in clients:
        try:
            ws.send(msg)
        except Exception:
            dead.add(ws)
    if dead:
        with _ws_lock:
            _ws_clients.difference_update(dead)


@sock.route("/ws/live")
def live_feed(ws):
    """WebSocket endpoint — keeps connection alive until client disconnects."""
    with _ws_lock:
        _ws_clients.add(ws)
    log.info("WebSocket client connected  (total=%d)", len(_ws_clients))
    try:
        while True:
            # Keep connection alive; actual data is pushed via _broadcast()
            msg = ws.receive(timeout=30)
            if msg is None:
                break
    except Exception:
        pass
    finally:
        with _ws_lock:
            _ws_clients.discard(ws)
        log.info("WebSocket client disconnected (total=%d)", len(_ws_clients))


# ─── Packet ingestion ─────────────────────────────────────────────────────────

def _validate_packet(data: dict):
    """Raise ValueError with a descriptive message if required fields missing."""
    required = ["src_id", "dest_id", "seq_num", "protocol",
                "hop_count", "send_time_ms"]
    missing  = [f for f in required if f not in data]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")
    if data["protocol"] not in (1, 2, 3):
        raise ValueError("protocol must be 1 (BLE), 2 (WiFi), or 3 (LoRa)")


@app.route("/api/packets", methods=["POST"])
def ingest_packet():
    """
    Called by gateway/protocol_bridge.py when a packet arrives.

    Expected JSON body — all fields from packet_format.py::Packet:
        src_id, dest_id, seq_num, protocol,
        hop_count, path, send_time_ms, rssi
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()

    try:
        _validate_packet(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 422

    received_at = time.time() * 1000

    db.insert_packet(
        src_id       = data["src_id"],
        dest_id      = data["dest_id"],
        seq_num      = data["seq_num"],
        protocol     = data["protocol"],
        hop_count    = data.get("hop_count", 0),
        path         = data.get("path", []),
        send_time_ms = data["send_time_ms"],
        rssi         = data.get("rssi", 0),
        received_at  = received_at,
    )

    # Compute latency and broadcast to live dashboard
    latency = received_at - data["send_time_ms"]
    _broadcast({
        "event":       "new_packet",
        "src_id":      data["src_id"],
        "seq_num":     data["seq_num"],
        "protocol":    data["protocol"],
        "hop_count":   data.get("hop_count", 0),
        "latency_ms":  round(latency, 2),
        "rssi":        data.get("rssi", 0),
        "received_at": received_at,
    })

    log.info("PKT  src=%-12s seq=%05d proto=%d hops=%d lat=%.1fms rssi=%d",
             data["src_id"], data["seq_num"], data["protocol"],
             data.get("hop_count", 0), latency, data.get("rssi", 0))

    return jsonify({"status": "ok", "latency_ms": round(latency, 2)}), 201


# ─── Query endpoints ──────────────────────────────────────────────────────────

@app.route("/api/packets", methods=["GET"])
def get_packets():
    limit = min(int(request.args.get("limit", 50)), 500)
    return jsonify(db.get_recent_packets(limit))


@app.route("/api/health", methods=["GET"])
def get_health():
    node_metrics = db.get_all_node_metrics()
    nodes        = compute_node_health(node_metrics)
    return jsonify(health_matrix_to_dict(nodes))


@app.route("/api/routes", methods=["GET"])
def get_routes():
    reports = analyse_routes()
    return jsonify(best_routes_to_dict(reports))


@app.route("/api/latency/<node_id>", methods=["GET"])
def get_latency_series(node_id):
    limit = min(int(request.args.get("limit", 100)), 1000)
    return jsonify(db.get_latency_series(node_id, limit))


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Network-wide summary — total packets, active nodes, avg latency."""
    packets = db.get_recent_packets(500)
    metrics = db.get_all_node_metrics()

    total_packets  = len(packets)
    active_nodes   = sum(1 for m in metrics
                         if (time.time()*1000 - m.get("last_seen", 0)) < 300_000)
    latencies      = [p["latency_ms"] for p in packets if p.get("latency_ms")]
    avg_latency    = round(sum(latencies)/len(latencies), 2) if latencies else 0.0
    avg_loss       = round(
        sum(m.get("packet_loss_pct", 0) for m in metrics) / len(metrics), 2
    ) if metrics else 0.0

    return jsonify({
        "total_packets":    total_packets,
        "active_nodes":     active_nodes,
        "total_nodes":      len(metrics),
        "avg_latency_ms":   avg_latency,
        "avg_packet_loss":  avg_loss,
        "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


# ─── Dashboard static file ────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(os.path.join(static_dir, "dashboard.html")):
        return send_from_directory(static_dir, "dashboard.html")
    return "<h2>IoT Backend running. Dashboard not found in /static/dashboard.html</h2>", 200


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))
    log.info("Starting IoT backend on %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, debug=False)