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
import socket as raw_socket
import logging
from datetime import datetime
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
GATEWAY_URL      = "http://10.202.64.140:8080"
DASHBOARD_PORT   = 9000
POLL_INTERVAL    = 2.0
HISTORY_MAX      = 100
UDP_MESH_PORT    = 5005   # Port nodes listen on for ROUTE_PREF

SHARED_KEY = b"mesh_secret_2106"   # Must match node.py and gateway.py

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dashboard-server")

# ─────────────────────────────────────────────
#  HMAC PACKET SIGNING
#  Uses the same key and serialisation as gateway.py's verify_packet_raw:
#    json.dumps(pkt, sort_keys=True, separators=(',', ':'))
#  node.py's _sorted_json() produces identical output for well-formed dicts,
#  so the signature will verify correctly on both ends.
# ─────────────────────────────────────────────
def sign_packet(pkt_dict: dict) -> dict:
    """Add HMAC-SHA256 'sig' field to pkt_dict in-place. Returns the dict."""
    pkt_dict.pop("sig", None)   # remove any stale sig first
    payload = json.dumps(pkt_dict, sort_keys=True, separators=(',', ':')).encode()
    sig = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
    pkt_dict["sig"] = sig
    return pkt_dict

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
                "timestamps": [],
                "latency_wifi": [],
                "latency_ble": [],
                "rssi_wifi": [],
                "rssi_ble": [],
                "packet_loss_wifi": [],
                "packet_loss_ble": [],
                "health_score": [],
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
                    cached_data["last_update"] = time.time()

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
                    "type": "update",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": cached_data["gateway_online"],
                    "health_matrix": cached_data["health_matrix"],
                    "topology": cached_data["topology"],
                    "history": cached_data["history"],
                })

            except httpx.ConnectError:
                cached_data["gateway_online"] = False
                log.warning("Gateway unreachable - retrying...")
                await broadcast_to_clients({
                    "type": "update",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix": cached_data["health_matrix"],
                    "topology": cached_data["topology"],
                    "history": cached_data["history"],
                })

            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.TimeoutException) as e:
                cached_data["gateway_online"] = False
                log.warning(f"Gateway timeout: {type(e).__name__}")
                await broadcast_to_clients({
                    "type": "update",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix": cached_data["health_matrix"],
                    "topology": cached_data["topology"],
                    "history": cached_data["history"],
                })

            except Exception as e:
                cached_data["gateway_online"] = False
                log.error(f"Poll error: {type(e).__name__}: {e}")
                await broadcast_to_clients({
                    "type": "update",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "gateway_online": False,
                    "health_matrix": cached_data["health_matrix"],
                    "topology": cached_data["topology"],
                    "history": cached_data["history"],
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
            "type": "update",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "gateway_online": cached_data["gateway_online"],
            "health_matrix": cached_data["health_matrix"],
            "topology": cached_data["topology"],
            "history": cached_data["history"],
        })
    except Exception:
        pass

    try:
        while True:
            data = await ws.receive_text()
    except (WebSocketDisconnect, RuntimeError, Exception):
        ws_clients.discard(ws)
        log.info(f"WebSocket client disconnected ({len(ws_clients)} remaining)")


# ─────────────────────────────────────────────
#  ROUTES: REST API
# ─────────────────────────────────────────────
@app.get("/api/health")
async def api_health():
    return {
        "server": "running",
        "gateway_online": cached_data["gateway_online"],
        "last_update": cached_data["last_update"],
        "connected_clients": len(ws_clients),
    }


@app.get("/api/history/{node_id}")
async def api_node_history(node_id: str):
    h = cached_data["history"].get(node_id)
    if h:
        return h
    return {"error": "Node not found"}


# ═══════════════════════════════════════════════════
#  PATH ANALYSIS — BACKEND CALCULATION
#  Same formulas as node.py compute_cost()
# ═══════════════════════════════════════════════════

WEIGHT_PROFILES = {
    "latency":  {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05},
    "cost":     {"w_latency": 0.3, "w_packet_loss": 0.5,  "w_power": 0.2},
    "power":    {"w_latency": 0.1, "w_packet_loss": 0.2,  "w_power": 0.7},
    "balanced": {"w_latency": 0.5, "w_packet_loss": 0.3,  "w_power": 0.2},
}


def compute_cost(latency_ms, packet_loss, power_cost, weights):
    """Same formula as node.py compute_cost."""
    return (weights["w_latency"] * (latency_ms / 100.0)
            + weights["w_packet_loss"] * packet_loss
            + weights["w_power"] * power_cost)


def rssi_to_power_cost(rssi):
    """Same formula as node.py: weaker RSSI = higher power cost."""
    return min(1.0, max(0.05, (-rssi - 50) / 40.0))


def analyze_hop(from_id, to_id, from_node, route_entry, weights):
    """Recalculate WiFi vs BLE cost for a single hop."""
    metrics = from_node.get("metrics", {})

    w_lat = (route_entry or {}).get("wifi_lat") or metrics.get("wifi_avg_latency_ms") or 0
    w_loss = metrics.get("wifi_packet_loss", 0)
    node_proto  = from_node.get("protocol", "WiFi")
    is_ble_node = "BLE" in node_proto
    _wifi_rssi_raw = metrics.get("wifi_rssi")
    if _wifi_rssi_raw is not None:
        w_rssi = _wifi_rssi_raw
    elif is_ble_node:
        w_rssi = -99
    else:
        w_rssi = from_node.get("rssi", -99)
    w_power = metrics.get("wifi_power_cost") or rssi_to_power_cost(w_rssi)

    b_lat = (route_entry or {}).get("ble_lat") or metrics.get("ble_avg_latency_ms") or 0
    b_loss = metrics.get("ble_packet_loss", 0)
    _ble_rssi_raw = metrics.get("ble_rssi")
    if _ble_rssi_raw is not None:
        b_rssi = _ble_rssi_raw
    elif is_ble_node:
        b_rssi = from_node.get("rssi", -99)
    else:
        b_rssi = -99
    b_power = metrics.get("ble_power_cost") or rssi_to_power_cost(b_rssi)

    w_avail = w_rssi > -99 or w_lat > 0
    b_avail = b_rssi > -99 or b_lat > 0

    w_cost = compute_cost(w_lat, w_loss, w_power, weights) if w_avail else 9999
    b_cost = compute_cost(b_lat, b_loss, b_power, weights) if b_avail else 9999

    if w_cost <= b_cost:
        best = "WiFi"
        best_cost, best_lat, best_power, best_rssi, best_loss = w_cost, w_lat, w_power, w_rssi, w_loss
    else:
        best = "BLE"
        best_cost, best_lat, best_power, best_rssi, best_loss = b_cost, b_lat, b_power, b_rssi, b_loss

    proto = from_node.get("protocol", "WiFi")
    node_decided = (route_entry or {}).get("best_protocol") or ("BLE" if "BLE" in proto else "WiFi")

    return {
        "from": from_id, "to": to_id,
        "protocol": best,
        "node_decided": node_decided,
        "changed": best != node_decided,
        "cost": round(best_cost, 6),
        "wifi_cost": round(w_cost, 6) if w_avail else None,
        "ble_cost": round(b_cost, 6) if b_avail else None,
        "latency": round(best_lat, 2),
        "power_cost": round(best_power, 4),
        "rssi": best_rssi,
        "packet_loss": round(best_loss, 4),
    }


def trace_path(src, dst, nodes, weights):
    """Trace routing path from src to dst, recalculating costs with given weights."""
    if src == dst:
        return []

    hops = []
    visited = set()
    current = src

    while current != dst and len(hops) < 10:
        if current in visited:
            break
        visited.add(current)

        if current == "GATEWAY":
            nd = nodes.get(dst)
            if nd:
                hops.append(analyze_hop("GATEWAY", dst, nd, None, weights))
            break

        from_node = nodes.get(current)
        if not from_node:
            break

        if dst == "GATEWAY":
            hops.append(analyze_hop(current, "GATEWAY", from_node, None, weights))
            break

        rt = from_node.get("routing_table", {})
        route_entry = rt.get(dst)

        if route_entry:
            next_hop = route_entry.get("next_hop", dst)
            hops.append(analyze_hop(current, next_hop, from_node, route_entry, weights))
            if next_hop == dst:
                break
            current = next_hop
        else:
            neighbours = from_node.get("neighbours", [])
            if dst in neighbours:
                hops.append(analyze_hop(current, dst, from_node, None, weights))
                break

            dst_node = nodes.get(dst)
            if dst_node and "GATEWAY" not in visited:
                hops.append(analyze_hop(current, "GATEWAY", from_node, None, weights))
                hops.append(analyze_hop("GATEWAY", dst, dst_node, None, weights))
                break

            hops.append({
                "from": current, "to": dst, "protocol": "?",
                "node_decided": "?", "changed": False, "unreachable": True,
                "cost": 0, "wifi_cost": None, "ble_cost": None,
                "latency": 0, "power_cost": 0, "rssi": -99, "packet_loss": 1.0,
            })
            break

    return hops


# ═══════════════════════════════════════════════════
#  SEND ROUTE_PREF DIRECTLY TO NODE VIA UDP
# ═══════════════════════════════════════════════════

BLE_PLACEHOLDERS = {"BLE-direct", "BLE-only", ""}

def get_node_ip(node_data: dict) -> str:
    """
    Return the best available IP for sending UDP to a node.
    Priority: sender_ip (real IP) → wifi_sender_ip → empty string.
    BLE placeholder values ("BLE-direct", "BLE-only") are treated as absent.
    """
    for field in ("sender_ip", "wifi_sender_ip"):
        ip = node_data.get(field, "")
        if ip and ip not in BLE_PLACEHOLDERS:
            return ip
    return ""



# ─────────────────────────────────────────────
#  API: PATH ANALYZE (calculate only)
# ─────────────────────────────────────────────
@app.post("/api/path_analyze")
async def api_path_analyze(request: Request):
    body = await request.json()
    src = body.get("src", "")
    dst = body.get("dst", "")
    mode = body.get("mode", "balanced")

    if not src or not dst:
        return {"error": "src and dst required"}
    if mode not in WEIGHT_PROFILES:
        return {"error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}

    nodes = cached_data.get("health_matrix", {}).get("nodes", {})
    weights = WEIGHT_PROFILES[mode]
    hops = trace_path(src, dst, nodes, weights)

    total_lat = sum(h.get("latency", 0) for h in hops)
    total_cost = sum(h.get("cost", 0) for h in hops if h.get("cost", 0) < 9999)

    return {
        "src": src, "dst": dst, "mode": mode,
        "weights": weights,
        "hops": hops,
        "total_hops": len(hops),
        "total_latency": round(total_lat, 2),
        "total_cost": round(total_cost, 6),
    }

# ─────────────────────────────────────────────
#  HELPER: Send route pref via gateway (not direct UDP)
# ─────────────────────────────────────────────
async def send_route_pref_via_gateway(node_id: str, mode: str, weights: dict):
    """
    Forward a route-preference update to a node via the gateway's /route_pref endpoint.
    The gateway decides delivery method automatically:
      - WiFi node  → signed UDP packet sent directly to node IP
      - BLE relay  → signed UDP to relay node, which BLE-advertises to target
      - BLE direct → gateway BLE-advertises directly to target

    Returns (ok: bool, message: str, delivery: str)
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/route_pref",
                json={"node_id": node_id, "mode": mode, "weights": weights}
            )
            data = resp.json()
            return (
                data.get("ok", False),
                data.get("message", "") or data.get("error", ""),
                data.get("delivery", ""),
            )
        except Exception as e:
            return False, str(e), ""


async def send_route_pref_batch_via_gateway(node_ids: list, mode: str, weights: dict):
    """
    Send route preference to multiple nodes via gateway batch endpoint.
    Falls back to per-node calls if batch endpoint unavailable.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/route_pref_batch",
                json={"node_ids": node_ids, "mode": mode, "weights": weights}
            )
            if resp.status_code == 200:
                return resp.json().get("node_results", {})
            elif resp.status_code == 404:
                log.info("[RoutePref] Batch not available, falling back to per-node")
        except Exception as e:
            log.warning(f"[RoutePref] Batch failed: {e}, falling back")

    # Fallback: one by one
    results = {}
    for nid in node_ids:
        ok, msg, delivery = await send_route_pref_via_gateway(nid, mode, weights)
        results[nid] = {"ok": ok, "message": msg, "delivery": delivery}
    return results


# ─────────────────────────────────────────────
#  API: PATH APPLY (calculate + send to nodes)
# ─────────────────────────────────────────────
@app.post("/api/path_apply")
async def api_path_apply(request: Request):
    body = await request.json()
    src  = body.get("src", "")
    dst  = body.get("dst", "")
    mode = body.get("mode", "balanced")

    if not src or not dst:
        return {"error": "src and dst required"}
    if mode not in WEIGHT_PROFILES:
        return {"error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}

    if not cached_data["gateway_online"]:
        return {"error": "Gateway is offline — cannot apply route preferences"}

    nodes   = cached_data.get("health_matrix", {}).get("nodes", {})
    weights = WEIGHT_PROFILES[mode]
    hops    = trace_path(src, dst, nodes, weights)

    # Collect unique node IDs in path (exclude GATEWAY)
    node_ids = set()
    for h in hops:
        if h["from"] != "GATEWAY":
            node_ids.add(h["from"])
        if h["to"] != "GATEWAY":
            node_ids.add(h["to"])

    if not node_ids:
        return {"error": "No nodes in path to update", "hops": hops}

    # Use batch endpoint for efficiency (handles WiFi, relay, BLE-direct)
    node_id_list = sorted(node_ids)
    results = await send_route_pref_batch_via_gateway(node_id_list, mode, weights)

    # Fill in any missing results
    for nid in node_ids:
        if nid not in results:
            results[nid] = {"ok": False, "message": "No response", "delivery": ""}

    success_count = sum(1 for r in results.values() if r.get("ok"))
    fail_count    = len(results) - success_count

    return {
        "src":           src,
        "dst":           dst,
        "mode":          mode,
        "weights":       weights,
        "hops":          hops,
        "node_results":  results,
        "success_count": success_count,
        "fail_count":    fail_count,
        "total_nodes":   len(node_ids),
    }


# ─────────────────────────────────────────────
#  API: ROUTE PREF SET  (single node)
# ─────────────────────────────────────────────
@app.post("/api/route_pref_set")
async def api_route_pref_set(request: Request):
    body = await request.json()
    node_id = body.get("node_id", "")
    mode    = body.get("mode", "balanced")

    if not node_id:
        return {"ok": False, "error": "node_id required"}
    if mode not in WEIGHT_PROFILES:
        return {"ok": False, "error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}

    nodes = cached_data.get("health_matrix", {}).get("nodes", {})
    node_data = nodes.get(node_id)
    if not node_data:
        return {"ok": False, "error": f"Node {node_id!r} not in health matrix"}

    weights = WEIGHT_PROFILES[mode]
    # Always route through the gateway — it handles WiFi (UDP) and BLE (advertisement)
    ok, msg, delivery = await send_route_pref_via_gateway(node_id, mode, weights)
    return {"ok": ok, "message": msg, "delivery": delivery, "mode": mode, "weights": weights}


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
                results[endpoint] = {"status": resp.status_code, "ok": resp.status_code == 200}
            except Exception as e:
                results[endpoint] = {"status": 0, "ok": False, "error": str(e)}
    return {
        "gateway_url": GATEWAY_URL,
        "endpoints": results,
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