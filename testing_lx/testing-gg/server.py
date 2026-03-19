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
import logging
from datetime import datetime
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
GATEWAY_URL = "http://10.200.176.43:8080"
DASHBOARD_PORT   = 9000                       # Port for this dashboard server
POLL_INTERVAL    = 2.0                        # Seconds between gateway polls
HISTORY_MAX      = 100                        # Max data points kept per node

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
    # Startup
    asyncio.create_task(poll_gateway())
    log.info(f"Dashboard server started on port {DASHBOARD_PORT}")
    log.info(f"Polling gateway at {GATEWAY_URL}")
    yield
    # Shutdown (nothing to clean up)

app = FastAPI(title="IoT Mesh Dashboard", lifespan=lifespan)

# Connected WebSocket clients
ws_clients: set[WebSocket] = set()

# Cached data from gateway
cached_data = {
    "health_matrix": {},
    "topology": {"edges": []},
    "history": {},         # { node_id: { "timestamps": [], "latency": [], "rssi": [], ... } }
    "last_update": 0,
    "gateway_online": False,
}

# ─────────────────────────────────────────────
#  HISTORY TRACKER
# ─────────────────────────────────────────────
def update_history(nodes: dict):
    """Append latest data points to per-node history arrays."""
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

        # Extract WiFi vs BLE metrics from routing table or metrics
        metrics = data.get("metrics", {})
        rt = data.get("routing_table", {})

        # WiFi metrics
        h["latency_wifi"].append(metrics.get("wifi_avg_latency_ms", data.get("avg_latency_ms", 0)))
        h["rssi_wifi"].append(metrics.get("wifi_rssi", data.get("rssi", -99)))
        h["packet_loss_wifi"].append(metrics.get("wifi_packet_loss", data.get("packet_loss", 0)))

        # BLE metrics
        h["latency_ble"].append(metrics.get("ble_avg_latency_ms", 0))
        h["rssi_ble"].append(metrics.get("ble_rssi", -99))
        h["packet_loss_ble"].append(metrics.get("ble_packet_loss", 0))

        h["health_score"].append(data.get("health_score", 0))

        # Trim to max history
        for key in h:
            if len(h[key]) > HISTORY_MAX:
                h[key] = h[key][-HISTORY_MAX:]

# ─────────────────────────────────────────────
#  GATEWAY POLLER
# ─────────────────────────────────────────────
async def broadcast_to_clients(payload):
    """Send payload to all connected WebSocket clients, removing dead ones."""
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    for d in dead:
        ws_clients.discard(d)


async def poll_gateway():
    """Background task: poll gateway REST API and push to WebSocket clients."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            try:
                # Fetch health matrix
                resp = await client.get(f"{GATEWAY_URL}/health_matrix")
                if resp.status_code == 200:
                    matrix_data = resp.json()
                    cached_data["health_matrix"] = matrix_data
                    cached_data["gateway_online"] = True
                    cached_data["last_update"] = time.time()

                    # Update history
                    nodes = matrix_data.get("nodes", {})
                    update_history(nodes)

                # Fetch topology
                try:
                    topo_resp = await client.get(f"{GATEWAY_URL}/topology")
                    if topo_resp.status_code == 200:
                        cached_data["topology"] = topo_resp.json()
                except Exception:
                    pass

                # Broadcast to all connected clients
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

            except Exception as e:
                log.error(f"Poll error: {type(e).__name__}: {e}")

            await asyncio.sleep(POLL_INTERVAL)

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.get("/")
async def serve_dashboard():
    """Serve the dashboard HTML."""
    html_path = Path(__file__).parent / "dashboard.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await ws.accept()
    ws_clients.add(ws)
    log.info(f"WebSocket client connected ({len(ws_clients)} total)")

    # Send initial state immediately
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
            # Keep connection alive, listen for client messages
            data = await ws.receive_text()
            # Could handle client commands here if needed
    except (WebSocketDisconnect, RuntimeError, Exception):
        ws_clients.discard(ws)
        log.info(f"WebSocket client disconnected ({len(ws_clients)} remaining)")


@app.get("/api/health")
async def api_health():
    """Quick health check."""
    return {
        "server": "running",
        "gateway_online": cached_data["gateway_online"],
        "last_update": cached_data["last_update"],
        "connected_clients": len(ws_clients),
    }


@app.get("/api/history/{node_id}")
async def api_node_history(node_id: str):
    """Get historical data for a specific node."""
    h = cached_data["history"].get(node_id)
    if h:
        return h
    return {"error": "Node not found"}


@app.post("/api/route_pref")
async def api_set_route_pref():
    """Proxy route preference change to the gateway."""
    from fastapi import Request
    # Read body manually since we don't have a Pydantic model
    pass

# Use a proper route with body parsing
from fastapi import Request

@app.post("/api/route_pref_set")
async def set_route_pref(request: Request):
    """Proxy route preference to gateway."""
    body = await request.json()
    node_id = body.get("node_id")
    mode = body.get("mode", "balanced")

    if not node_id:
        return {"error": "node_id required"}

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/route_pref",
                json={"node_id": node_id, "mode": mode}
            )
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"Gateway returned {resp.status_code}"}
        except Exception as e:
            return {"error": f"Gateway unreachable: {e}"}

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