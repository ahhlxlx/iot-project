"""
═══════════════════════════════════════════════════════════════
  IoT Mesh Network Dashboard Server
  Connects to gateway.py (Flask on port 8080) and serves a
  real-time web dashboard with WebSocket live updates.

  Run:  python server.py
  Open: http://localhost:9000
═══════════════════════════════════════════════════════════════
  Requirements:
    pip install fastapi uvicorn httpx websockets
═══════════════════════════════════════════════════════════════
"""

import asyncio
import json
import time
import os
import hmac
import hashlib
import logging
from datetime import datetime
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
GATEWAY_URL      = "http://10.202.64.43:8080"
DASHBOARD_PORT   = 9000
POLL_INTERVAL    = 2.0
HISTORY_MAX      = 100

SHARED_KEY = b"mesh_secret_2106"

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dashboard-server")

# ─────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(application):
    asyncio.create_task(poll_gateway())
    log.info(f"Dashboard server started on port {DASHBOARD_PORT}")
    log.info(f"Polling gateway at {GATEWAY_URL}")
    yield

app = FastAPI(title="IoT Mesh Dashboard", lifespan=lifespan)

ws_clients: set[WebSocket] = set()

cached_data = {
    "health_matrix": {},
    "topology": {"edges": []},
    "history": {},
    "last_update": 0,
    "gateway_online": False,
}

# ─────────────────────────────────────────────
#  HISTORY TRACKER
# ─────────────────────────────────────────────
def update_history(nodes: dict):
    now = datetime.now().strftime("%H:%M:%S")
    history = cached_data["history"]

    for node_id, data in nodes.items():
        if node_id not in history:
            history[node_id] = {
                "timestamps":       [],
                "latency_wifi":     [],
                "latency_ble":      [],
                "rssi_wifi":        [],
                "rssi_ble":         [],
                "packet_loss_wifi": [],
                "packet_loss_ble":  [],
                "health_score":     [],
            }
        h = history[node_id]
        h["timestamps"].append(now)

        metrics = data.get("metrics", {})
        h["latency_wifi"].append(metrics.get("wifi_avg_latency_ms", data.get("avg_latency_ms", 0)))
        h["rssi_wifi"].append(metrics.get("wifi_rssi", data.get("rssi", -99)))
        h["packet_loss_wifi"].append(metrics.get("wifi_packet_loss", data.get("packet_loss", 0)))
        h["latency_ble"].append(metrics.get("ble_avg_latency_ms", 0))
        h["rssi_ble"].append(metrics.get("ble_rssi", -99))
        h["packet_loss_ble"].append(metrics.get("ble_packet_loss", 0))
        h["health_score"].append(data.get("health_score", 0))

        for key in h:
            if len(h[key]) > HISTORY_MAX:
                h[key] = h[key][-HISTORY_MAX:]


# ─────────────────────────────────────────────
#  GATEWAY POLLER
# ─────────────────────────────────────────────
async def broadcast_to_clients(payload):
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    for d in dead:
        ws_clients.discard(d)


async def poll_gateway():
    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            try:
                resp = await client.get(f"{GATEWAY_URL}/health_matrix")
                if resp.status_code == 200:
                    matrix_data = resp.json()
                    cached_data["health_matrix"] = matrix_data
                    cached_data["gateway_online"] = True
                    cached_data["last_update"]    = time.time()
                    nodes = matrix_data.get("nodes", {})
                    update_history(nodes)
                else:
                    cached_data["gateway_online"] = False
                    log.warning(f"Gateway returned HTTP {resp.status_code}")

                try:
                    topo_resp = await client.get(f"{GATEWAY_URL}/topology")
                    if topo_resp.status_code == 200:
                        cached_data["topology"] = topo_resp.json()
                except Exception:
                    pass

                await broadcast_to_clients({
                    "type":           "update",
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": cached_data["gateway_online"],
                    "health_matrix":  cached_data["health_matrix"],
                    "topology":       cached_data["topology"],
                    "history":        cached_data["history"],
                })

            except httpx.ConnectError:
                cached_data["gateway_online"] = False
                log.warning("Gateway unreachable - retrying...")
                await broadcast_to_clients({
                    "type":           "update",
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix":  cached_data["health_matrix"],
                    "topology":       cached_data["topology"],
                    "history":        cached_data["history"],
                })

            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.TimeoutException) as e:
                cached_data["gateway_online"] = False
                log.warning(f"Gateway timeout: {type(e).__name__}")
                await broadcast_to_clients({
                    "type":           "update",
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix":  cached_data["health_matrix"],
                    "topology":       cached_data["topology"],
                    "history":        cached_data["history"],
                })

            except Exception as e:
                cached_data["gateway_online"] = False
                log.error(f"Poll error: {type(e).__name__}: {e}")
                await broadcast_to_clients({
                    "type":           "update",
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix":  cached_data["health_matrix"],
                    "topology":       cached_data["topology"],
                    "history":        cached_data["history"],
                })

            await asyncio.sleep(POLL_INTERVAL)


# ─────────────────────────────────────────────
#  ROUTES: HTML PAGES
# ─────────────────────────────────────────────
@app.get("/")
async def serve_dashboard():
    html_path = Path(__file__).parent / "dashboard.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/path")
async def serve_path_analysis():
    html_path = Path(__file__).parent / "path_analysis.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────
#  ROUTES: WEBSOCKET
# ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    log.info(f"WebSocket client connected ({len(ws_clients)} total)")

    try:
        await ws.send_json({
            "type":           "update",
            "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "gateway_online": cached_data["gateway_online"],
            "health_matrix":  cached_data["health_matrix"],
            "topology":       cached_data["topology"],
            "history":        cached_data["history"],
        })
    except Exception:
        pass

    try:
        while True:
            await ws.receive_text()
    except (WebSocketDisconnect, RuntimeError, Exception):
        ws_clients.discard(ws)
        log.info(f"WebSocket client disconnected ({len(ws_clients)} remaining)")


# ─────────────────────────────────────────────
#  ROUTES: REST API
# ─────────────────────────────────────────────
@app.get("/api/health")
async def api_health():
    return {
        "server":           "running",
        "gateway_online":   cached_data["gateway_online"],
        "last_update":      cached_data["last_update"],
        "connected_clients": len(ws_clients),
    }


@app.get("/api/history/{node_id}")
async def api_node_history(node_id: str):
    h = cached_data["history"].get(node_id)
    if h:
        return h
    return {"error": "Node not found"}


# ═══════════════════════════════════════════════════
#  PATH ANALYSIS — VIEW-ONLY BACKEND CALCULATION
#
#  Recalculates WiFi vs BLE cost for every hop using
#  the selected weight profile.  Works for WiFi nodes,
#  BLE-only nodes, and mixed paths equally — no UDP
#  delivery is attempted.  Pure read from cached data.
#
#  Cost formula (mirrors node_main.py compute_cost):
#    cost = w_latency*(lat/100) + w_packet_loss*loss + w_power*power
# ═══════════════════════════════════════════════════

WEIGHT_PROFILES = {
    "latency":  {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05},
    "cost":     {"w_latency": 0.3, "w_packet_loss": 0.5,  "w_power": 0.2 },
    "power":    {"w_latency": 0.1, "w_packet_loss": 0.2,  "w_power": 0.7 },
    "balanced": {"w_latency": 0.5, "w_packet_loss": 0.3,  "w_power": 0.2 },
}


def compute_cost(latency_ms: float, packet_loss: float,
                 power_cost: float, weights: dict) -> float:
    """Mirrors node_main.py compute_cost() exactly."""
    return (weights["w_latency"]     * (latency_ms / 100.0)
            + weights["w_packet_loss"] * packet_loss
            + weights["w_power"]       * power_cost)


def rssi_to_power_cost(rssi: int) -> float:
    """Mirrors node_main.py power cost formula."""
    return min(1.0, max(0.05, (-rssi - 50) / 40.0))


def analyze_hop(from_id: str, to_id: str,
                from_node: dict, route_entry: dict | None,
                weights: dict) -> dict:
    """
    For a single hop (from_id → to_id), calculate the WiFi cost and
    BLE cost independently using the given weight profile, then elect
    the cheaper one as the recommended protocol.

    Works regardless of whether the node is WiFi-only, BLE-only, or dual.
    When a protocol has no data (RSSI=-99, latency=0) it is treated as
    unavailable (cost=9999) so the other protocol wins automatically.
    """
    metrics     = from_node.get("metrics", {})
    node_proto  = from_node.get("protocol", "WiFi")
    is_ble_node = "BLE" in node_proto

    # ── WiFi metrics ───────────────────────────────────────────────
    w_lat  = (route_entry or {}).get("wifi_lat") or metrics.get("wifi_avg_latency_ms") or 0.0
    w_loss = metrics.get("wifi_packet_loss", 0.0)
    _w_rssi_raw = metrics.get("wifi_rssi")
    if _w_rssi_raw is not None:
        w_rssi = _w_rssi_raw
    elif is_ble_node:
        w_rssi = -99          # BLE-only node has no WiFi RSSI
    else:
        w_rssi = from_node.get("rssi", -99)
    w_power = metrics.get("wifi_power_cost") or rssi_to_power_cost(w_rssi)

    # ── BLE metrics ────────────────────────────────────────────────
    b_lat  = (route_entry or {}).get("ble_lat") or metrics.get("ble_avg_latency_ms") or 0.0
    b_loss = metrics.get("ble_packet_loss", 0.0)
    _b_rssi_raw = metrics.get("ble_rssi")
    if _b_rssi_raw is not None:
        b_rssi = _b_rssi_raw
    elif is_ble_node:
        b_rssi = from_node.get("rssi", -99)
    else:
        b_rssi = -99          # WiFi-only node has no BLE RSSI
    b_power = metrics.get("ble_power_cost") or rssi_to_power_cost(b_rssi)

    # ── Availability ───────────────────────────────────────────────
    w_avail = w_rssi > -99 or w_lat > 0
    b_avail = b_rssi > -99 or b_lat > 0

    w_cost = compute_cost(w_lat, w_loss, w_power, weights) if w_avail else 9999.0
    b_cost = compute_cost(b_lat, b_loss, b_power, weights) if b_avail else 9999.0

    # ── Elect winner ───────────────────────────────────────────────
    if w_cost <= b_cost:
        best        = "WiFi"
        best_cost   = w_cost
        best_lat    = w_lat
        best_power  = w_power
        best_rssi   = w_rssi
        best_loss   = w_loss
    else:
        best        = "BLE"
        best_cost   = b_cost
        best_lat    = b_lat
        best_power  = b_power
        best_rssi   = b_rssi
        best_loss   = b_loss

    # What protocol the node itself currently uses (from its own routing table)
    node_decided = ((route_entry or {}).get("best_protocol")
                    or ("BLE" if is_ble_node else "WiFi"))

    return {
        "from":         from_id,
        "to":           to_id,
        "protocol":     best,                           # recommended by our weight profile
        "node_decided": node_decided,                   # what the node itself chose
        "changed":      best != node_decided,           # True = our profile disagrees
        "cost":         round(best_cost, 6),
        "wifi_cost":    round(w_cost,    6) if w_avail else None,
        "ble_cost":     round(b_cost,    6) if b_avail else None,
        "latency":      round(best_lat,  2),
        "power_cost":   round(best_power,4),
        "rssi":         best_rssi,
        "packet_loss":  round(best_loss, 4),
    }


def trace_path(src: str, dst: str, nodes: dict, weights: dict) -> list[dict]:
    """
    Follow next_hop pointers from src toward dst, recalculating each
    hop's WiFi vs BLE cost with the given weight profile.

    For BLE-only nodes that have no routing table entries between each
    other, the path falls back to src → GATEWAY → dst so that something
    meaningful is always shown.

    Returns a list of hop dicts (empty list if src == dst).
    """
    if src == dst:
        return []

    hops: list[dict] = []
    visited: set[str] = set()
    current = src

    while current != dst and len(hops) < 10:
        if current in visited:
            break
        visited.add(current)

        # ── Already at GATEWAY, one final hop to dst ───────────────
        if current == "GATEWAY":
            nd = nodes.get(dst)
            if nd:
                hops.append(analyze_hop("GATEWAY", dst, nd, None, weights))
            break

        from_node = nodes.get(current)
        if not from_node:
            break

        # ── Direct to GATEWAY ──────────────────────────────────────
        if dst == "GATEWAY":
            hops.append(analyze_hop(current, "GATEWAY", from_node, None, weights))
            break

        # ── Check routing table for explicit route to dst ──────────
        rt          = from_node.get("routing_table", {})
        route_entry = rt.get(dst)

        if route_entry:
            next_hop = route_entry.get("next_hop", dst)
            hops.append(analyze_hop(current, next_hop, from_node, route_entry, weights))
            if next_hop == dst:
                break
            current = next_hop

        else:
            # ── No direct route: check neighbour list ──────────────
            neighbours = from_node.get("neighbours", [])
            if dst in neighbours:
                hops.append(analyze_hop(current, dst, from_node, None, weights))
                break

            # ── Fallback: route via GATEWAY ────────────────────────
            # Covers BLE-only ↔ BLE-only and any node pair with no
            # direct routing table entry.  Both nodes are reachable by
            # the gateway (it collected their data), so the path is
            # always: src → GATEWAY → dst.
            dst_node = nodes.get(dst)
            if dst_node and "GATEWAY" not in visited:
                hops.append(analyze_hop(current, "GATEWAY", from_node, None, weights))
                hops.append(analyze_hop("GATEWAY", dst,     dst_node,  None, weights))
                break

            # ── Truly unreachable ──────────────────────────────────
            hops.append({
                "from": current, "to": dst,
                "protocol": "?", "node_decided": "?",
                "changed": False, "unreachable": True,
                "cost": 0, "wifi_cost": None, "ble_cost": None,
                "latency": 0, "power_cost": 0,
                "rssi": -99, "packet_loss": 1.0,
            })
            break

    return hops


# ─────────────────────────────────────────────
#  API: PATH ANALYZE  (view-only, no side effects)
#
#  Works for:
#    • WiFi-only nodes
#    • BLE-only nodes
#    • Mixed WiFi + BLE paths
#    • Any combination through GATEWAY
#
#  Does NOT send any packets to nodes.
# ─────────────────────────────────────────────
@app.post("/api/path_analyze")
async def api_path_analyze(request: Request):
    body = await request.json()
    src  = body.get("src", "")
    dst  = body.get("dst", "")
    mode = body.get("mode", "balanced")

    if not src or not dst:
        return {"error": "src and dst required"}
    if mode not in WEIGHT_PROFILES:
        return {"error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}

    nodes   = cached_data.get("health_matrix", {}).get("nodes", {})
    weights = WEIGHT_PROFILES[mode]
    hops    = trace_path(src, dst, nodes, weights)

    total_lat  = sum(h.get("latency", 0)                            for h in hops)
    total_cost = sum(h.get("cost",    0) for h in hops
                     if h.get("cost", 0) < 9999)
    avg_power  = (sum(h.get("power_cost", 0) for h in hops) / len(hops)
                  if hops else 0)

    # Dominant protocol: whichever wins more hops
    wifi_hops = sum(1 for h in hops if h.get("protocol") == "WiFi")
    ble_hops  = sum(1 for h in hops if h.get("protocol") == "BLE")

    return {
        "src":             src,
        "dst":             dst,
        "mode":            mode,
        "weights":         weights,
        "hops":            hops,
        "total_hops":      len(hops),
        "total_latency":   round(total_lat,  2),
        "total_cost":      round(total_cost, 6),
        "avg_power_cost":  round(avg_power,  4),
        "wifi_hops":       wifi_hops,
        "ble_hops":        ble_hops,
        "dominant_proto":  "WiFi" if wifi_hops >= ble_hops else "BLE",
    }


# ─────────────────────────────────────────────
#  API: GATEWAY DIAGNOSTIC
# ─────────────────────────────────────────────
@app.get("/api/gateway_check")
async def api_gateway_check():
    results = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for endpoint in ["/ping", "/health_matrix", "/summary", "/topology"]:
            try:
                resp = await client.get(f"{GATEWAY_URL}{endpoint}")
                results[endpoint] = {"status": resp.status_code,
                                     "ok":     resp.status_code == 200}
            except Exception as e:
                results[endpoint] = {"status": 0, "ok": False, "error": str(e)}
    return {
        "gateway_url":    GATEWAY_URL,
        "endpoints":      results,
        "gateway_online": cached_data["gateway_online"],
    }


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("═" * 55)
    print("  IoT Mesh Network Dashboard Server")
    print(f"  Dashboard:  http://localhost:{DASHBOARD_PORT}")
    print(f"  Gateway:    {GATEWAY_URL}")
    print("═" * 55)
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT, log_level="info")