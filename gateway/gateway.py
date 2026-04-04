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
  - BLE ROUTE_PREF advertising for BLE-only nodes
===================================================
Requirements:
    pip install flask bleak
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
import subprocess
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

# Route preference weight profiles (must match server.py and frontend)
WEIGHT_PROFILES = {
    "latency":  {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05},
    "cost":     {"w_latency": 0.3, "w_packet_loss": 0.5,  "w_power": 0.2},
    "power":    {"w_latency": 0.1, "w_packet_loss": 0.2,  "w_power": 0.7},
    "balanced": {"w_latency": 0.5, "w_packet_loss": 0.3,  "w_power": 0.2},
}

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

# Suppress noisy internal debug output from the BLE scanning libraries
logging.getLogger("bleak").setLevel(logging.WARNING)
logging.getLogger("dbus_fast").setLevel(logging.WARNING)
logging.getLogger("bleak.backends.bluezdbus.scanner").setLevel(logging.WARNING)

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
BLE_PKT_TYPE_ROUTE_PREF = 0x05

# Mode name ↔ byte mapping for BLE ROUTE_PREF encoding
_ROUTE_MODE_WMAP = {"balanced": 0, "latency": 1, "cost": 2, "power": 3}

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
seq_tracker = {}   # { (node_id, protocol): { last_seq, expected_seq } }

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
    route_mode = pkt.get("route_mode", None)
    weights    = pkt.get("weights",    None)
    hops     = pkt.get("hop_count", 0)
    protocol = pkt.get("protocol", "WiFi")

    # Use wifi_avg_latency_ms (the actual key node.py sends); fall back to ble if wifi absent
    latency   = metrics.get("wifi_avg_latency_ms", metrics.get("ble_avg_latency_ms", 0.0))
    # Use wifi_packet_loss (the actual key node.py sends); fall back to ble if wifi absent
    loss      = metrics.get("wifi_packet_loss",    metrics.get("ble_packet_loss",    0.0))
    throughput= metrics.get("throughput_est", 0.0)

    with matrix_lock:
        existing = health_matrix.get(node_id, {})

        # ── Resolve the correct sender_ip ──────────────────────────────────
        BLE_PLACEHOLDERS  = ("BLE-direct", "BLE-only", "")
        relayed_by        = pkt.get("relayed_by", "")
        is_relayed        = bool(relayed_by and relayed_by != node_id)
        self_reported_ip  = pkt.get("ip", "")
        existing_ip       = existing.get("sender_ip", "")
        existing_wifi_ip  = existing.get("wifi_sender_ip", "")

        if self_reported_ip and self_reported_ip not in BLE_PLACEHOLDERS \
                and self_reported_ip != "0.0.0.0":
            resolved_ip    = self_reported_ip
            wifi_sender_ip = self_reported_ip
        elif not is_relayed and sender_ip not in BLE_PLACEHOLDERS:
            resolved_ip    = sender_ip
            wifi_sender_ip = sender_ip
        elif existing_ip and existing_ip not in BLE_PLACEHOLDERS:
            resolved_ip    = existing_ip
            wifi_sender_ip = existing_wifi_ip if existing_wifi_ip not in BLE_PLACEHOLDERS \
                             else existing_ip
        else:
            resolved_ip    = sender_ip if sender_ip not in BLE_PLACEHOLDERS else "BLE-only"
            wifi_sender_ip = existing_wifi_ip if existing_wifi_ip not in BLE_PLACEHOLDERS else ""

        sender_ip = resolved_ip

        # ── Sequence number tracking ───────────────────────────────
        seq_key = (node_id, protocol)
        if seq_key not in seq_tracker:
            seq_tracker[seq_key] = {"last_seq": seq, "expected_seq": seq + 1,
                                     "total_received": 1, "total_lost": 0}
        else:
            st     = seq_tracker[seq_key]
            gap    = seq - st["last_seq"] - 1
            if gap > 0:
                st["total_lost"] += gap
                log.warning(f"[{node_id}/{protocol}] Detected {gap} lost packet(s) "
                            f"(seq {st['last_seq']+1}–{seq-1})")
            elif gap < -1:
                log.debug(f"[{node_id}/{protocol}] Out-of-order or wrapped seq: "
                          f"last={st['last_seq']} new={seq}")
            st["total_received"] += 1
            st["last_seq"]        = seq
            st["expected_seq"]    = seq + 1

        st          = seq_tracker[seq_key]
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
            "wifi_sender_ip"  : wifi_sender_ip,
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
            "metrics"         : metrics,
            "route_mode"      : route_mode or existing.get("route_mode", "balanced"),
            "route_weights"   : weights    or existing.get("route_weights", {}),
            "route_ack_time"  : existing.get("route_ack_time"),
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
                "metrics"    : {},
            }
            log.info(f"[Hello] New node discovered: {node_id} @ {sender_ip}")
        else:
            health_matrix[node_id]["last_seen"]     = now
            health_matrix[node_id]["last_seen_str"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            health_matrix[node_id]["rssi"]          = rssi
            health_matrix[node_id]["routing_table"] = rt
            health_matrix[node_id]["protocol"]      = pkt.get("protocol", health_matrix[node_id].get("protocol", "WiFi"))
            health_matrix[node_id]["sender_ip"]     = sender_ip


# ─────────────────────────────────────────────
#  PROCESS ROUTE_PREF_ACK
# ─────────────────────────────────────────────
def process_route_pref_ack(pkt, sender_ip):
    node_id = pkt.get("node_id")
    if not node_id:
        return
    mode    = pkt.get("mode", "balanced")
    weights = {
        "w_latency"    : pkt.get("w_latency"),
        "w_packet_loss": pkt.get("w_packet_loss"),
        "w_power"      : pkt.get("w_power"),
    }
    delivery   = pkt.get("delivery", "UDP")
    relayed_by = pkt.get("relayed_by", "")
    relay_ok   = pkt.get("relay_ok", True)
    now = time.time()

    with matrix_lock:
        if node_id in health_matrix:
            health_matrix[node_id]["route_mode"]    = mode
            health_matrix[node_id]["route_weights"] = weights
            # Only mark as confirmed if delivery actually succeeded.
            # A relay ACK with relay_ok=False means the BLE broadcast
            # was attempted but the relay couldn't reach the target.
            if relay_ok:
                health_matrix[node_id]["route_ack_time"]= now
            if sender_ip not in ("BLE-direct", "BLE-only", ""):
                # Don't overwrite sender_ip for relay ACKs — the relay's IP
                # is not the target node's IP
                if not relayed_by:
                    health_matrix[node_id]["sender_ip"]     = sender_ip
                    health_matrix[node_id]["wifi_sender_ip"]= sender_ip

    via_str = f" via relay {relayed_by}" if relayed_by else ""
    log.info(f"[RoutePref] ACK from {node_id}{via_str}: mode={mode} "
             f"delivery={delivery} "
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

            if not verify_packet_raw(raw):
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
#  GATEWAY BLE ROUTE_PREF ADVERTISING
#  Uses hcitool on the Raspberry Pi to directly
#  broadcast ROUTE_PREF packets to BLE-only nodes.
# ─────────────────────────────────────────────

_gw_ble_route_pref_seq = 0
_gw_ble_adv_lock = threading.Lock()

def _encode_route_pref_ble(target_node_id, w_latency, w_packet_loss,
                           w_power, mode, seq):
    """
    Encode a 19-byte ROUTE_PREF BLE manufacturer-data payload.
    Matches ble_code.encode_route_pref() exactly.
    """
    raw_b  = target_node_id.encode()[:7]
    node_b = raw_b + b'\x00' * (7 - len(raw_b))
    mode_byte = _ROUTE_MODE_WMAP.get(mode, 0)
    return (BLE_MAGIC
            + bytes([BLE_PKT_TYPE_ROUTE_PREF])
            + node_b
            + bytes([
                min(255, int(w_latency * 200)),
                min(255, int(w_packet_loss * 200)),
                min(255, int(w_power * 200)),
                mode_byte,
                seq & 0xFF,
                0, 0, 0, 0
            ]))


def gateway_ble_advertise_route_pref(target_node_id, w_latency, w_packet_loss,
                                     w_power, mode, duration_s=3.0):
    """
    Directly BLE-advertise a ROUTE_PREF from the Raspberry Pi gateway.

    Uses hcitool HCI commands to set manufacturer-specific advertising data
    and enable advertising for `duration_s` seconds.  The single advertisement
    carries one seq number; the Pico's scan window (~50ms every 100ms) will
    catch it multiple times during the hold period but dedup ensures only
    one application.

    Args:
        target_node_id : NODE_ID of the BLE-only target
        w_latency      : latency weight
        w_packet_loss  : packet-loss weight
        w_power        : power weight
        mode           : "balanced" | "latency" | "cost" | "power"
        duration_s     : how long to advertise (default 3s)

    Returns: (ok: bool, message: str)
    """
    global _gw_ble_route_pref_seq

    if not BLE_SCAN_ENABLED:
        return False, "BLE not available on gateway"

    with _gw_ble_adv_lock:
        try:
            # Increment seq ONCE per delivery attempt.  All `repeat` bursts
            # carry the same seq so the Pico's IRQ dedup accepts only the
            # first one — the repeats exist purely for radio reliability.
            _gw_ble_route_pref_seq = (_gw_ble_route_pref_seq + 1) & 0xFF
            payload = _encode_route_pref_ble(
                target_node_id, w_latency, w_packet_loss, w_power,
                mode, _gw_ble_route_pref_seq
            )

            # Wrap in BLE AD structure: [length, type=0xFF, payload...]
            ad = bytes([len(payload) + 1, 0xFF]) + payload
            ad_len = len(ad)

            # Build hcitool hex args (1 length byte + 31 data bytes)
            hex_args = [f'{ad_len:02X}'] + [f'{b:02X}' for b in ad]
            while len(hex_args) < 32:
                hex_args.append('00')

            # Set advertising data (OGF=0x08 OCF=0x0008)
            cmd_set = ['sudo', 'hcitool', '-i', 'hci0', 'cmd',
                       '0x08', '0x0008'] + hex_args
            result = subprocess.run(cmd_set, timeout=2, capture_output=True)
            if result.returncode != 0:
                log.warning(f"[BLE-GW] hcitool set adv data failed: "
                            f"{result.stderr.decode().strip()}")

            # Enable advertising (OGF=0x08 OCF=0x000A)
            cmd_on = ['sudo', 'hcitool', '-i', 'hci0', 'cmd',
                      '0x08', '0x000A', '01']
            subprocess.run(cmd_on, timeout=2, capture_output=True)

            # Hold advertising for the full duration so scanners can pick it up
            time.sleep(duration_s)

            # Disable advertising
            cmd_off = ['sudo', 'hcitool', '-i', 'hci0', 'cmd',
                       '0x08', '0x000A', '00']
            subprocess.run(cmd_off, timeout=2, capture_output=True)

            log.info(f"[BLE-GW] ROUTE_PREF advertised for {target_node_id}: "
                     f"mode={mode} ({duration_s}s hold)")
            return True, f"BLE ROUTE_PREF advertised for {target_node_id}"

        except FileNotFoundError:
            msg = "hcitool not found — install bluez package"
            log.error(f"[BLE-GW] {msg}")
            return False, msg
        except subprocess.TimeoutExpired:
            msg = "hcitool command timed out"
            log.error(f"[BLE-GW] {msg}")
            return False, msg
        except Exception as e:
            msg = f"BLE advertising error: {e}"
            log.error(f"[BLE-GW] {msg}")
            return False, msg


# ─────────────────────────────────────────────
#  ROUTE PREF DELIVERY LOGIC
#  Unified function for delivering to any node type
# ─────────────────────────────────────────────

BLE_ONLY_VALUES = {"BLE-direct", "BLE-only", ""}

def _best_ip(nd):
    """Return the best known WiFi IP for a node entry, or '' if BLE-only."""
    for field in ("wifi_sender_ip", "sender_ip"):
        ip = nd.get(field, "")
        if ip and ip not in BLE_ONLY_VALUES:
            return ip
    return ""


def deliver_route_pref(node_id, mode, weights, all_nodes):
    """
    Deliver a ROUTE_PREF to a single node. Tries all available delivery methods
    in priority order:

    1. Direct UDP — if the node has a known WiFi IP
    2. Relay via dual-protocol neighbour — WiFi to relay, relay BLE-advertises
    3. Direct BLE advertising from gateway — hcitool on Raspberry Pi

    Args:
        node_id   : target NODE_ID
        mode      : "balanced" | "latency" | "cost" | "power"
        weights   : {"w_latency": ..., "w_packet_loss": ..., "w_power": ...}
        all_nodes : snapshot of health_matrix

    Returns: (ok: bool, message: str, delivery: str)
    """
    node_data = all_nodes.get(node_id)
    if not node_data:
        return False, f"Node {node_id!r} not in health matrix", "none"

    def _build_signed_pkt(target_node_id):
        pkt = {
            "type"         : "ROUTE_PREF",
            "node_id"      : "GATEWAY",
            "target"       : target_node_id,
            "mode"         : mode,
            "w_latency"    : weights.get("w_latency",     0.5),
            "w_packet_loss": weights.get("w_packet_loss", 0.3),
            "w_power"      : weights.get("w_power",       0.2),
            "timestamp"    : int(time.time()),
        }
        payload  = json.dumps(pkt, sort_keys=True, separators=(',', ':')).encode()
        pkt["sig"] = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
        return pkt

    def _udp_send(ip, pkt):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(json.dumps(pkt).encode(), (ip, MESH_PORT))
            sock.close()
            return True, f"sent to {ip}"
        except Exception as e:
            return False, str(e)

    # ── Method 1: Direct UDP to node's WiFi IP ──────────────────────────
    target_ip = _best_ip(node_data)
    if target_ip:
        pkt = _build_signed_pkt(node_id)
        ok, detail = _udp_send(target_ip, pkt)
        if ok:
            log.info(f"[RoutePref] UDP → {node_id} @ {target_ip}  mode={mode}")
            return True, f"ROUTE_PREF sent to {node_id} @ {target_ip}", "UDP"
        else:
            log.warning(f"[RoutePref] UDP failed for {node_id} @ {target_ip}: {detail}")
            # Fall through to try relay/BLE methods

    # ── Method 2: Relay via dual-protocol neighbour ─────────────────────
    # Find a node that:
    #   (a) has a real WiFi IP (so we can UDP to it), AND
    #   (b) lists node_id as a neighbour (so it can reach the BLE target)
    relay_ip   = ""
    relay_name = ""
    for nid, nd in all_nodes.items():
        if nid == node_id:
            continue
        if _best_ip(nd) and node_id in nd.get("neighbours", []):
            relay_ip   = _best_ip(nd)
            relay_name = nid
            break

    if relay_ip:
        # Send the ROUTE_PREF with the BLE-only node as target;
        # the relay node will detect it's not for itself and
        # BLE-advertise it for the BLE-only neighbour.
        pkt = _build_signed_pkt(node_id)
        ok, detail = _udp_send(relay_ip, pkt)
        if ok:
            log.info(f"[RoutePref] Relay → {node_id} via {relay_name} @ {relay_ip}  mode={mode}")
            return True, (f"ROUTE_PREF sent to {node_id} via relay "
                         f"{relay_name} @ {relay_ip}"), "relay"
        else:
            log.warning(f"[RoutePref] Relay failed for {node_id} via {relay_name}: {detail}")

    # ── Method 3: Direct BLE advertising from gateway ───────────────────
    if BLE_SCAN_ENABLED:
        ok, msg = gateway_ble_advertise_route_pref(
            node_id,
            weights.get("w_latency", 0.5),
            weights.get("w_packet_loss", 0.3),
            weights.get("w_power", 0.2),
            mode
        )
        if ok:
            return True, msg, "BLE-direct"
        log.warning(f"[RoutePref] BLE-direct failed for {node_id}: {msg}")

    # ── All methods exhausted ───────────────────────────────────────────
    return False, (f"No delivery path for {node_id}: no WiFi IP, "
                   f"no reachable relay, BLE advertising failed"), "none"


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
            "nodes"            : copy.deepcopy(health_matrix)
        }
    return jsonify(data)


@flask_app.route("/node/<node_id>", methods=["GET"])
def api_node(node_id):
    """Single node details."""
    with matrix_lock:
        node = health_matrix.get(node_id)
        node_copy = copy.deepcopy(node) if node else None
    if node_copy:
        return jsonify(node_copy)
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
                    "latency"  : route.get("avg_latency_ms"),
                    "cost"     : route.get("cost"),
                    "protocol" : route.get("best_protocol"),
                })
    return jsonify({"edges": edges})


@flask_app.route("/ping", methods=["GET"])
def api_ping():
    return jsonify({"status": "ok", "gateway": "running"})


@flask_app.route("/route_pref", methods=["POST"])
def api_route_pref():
    """
    Push a routing-weight update to a single node.  Handles all node types
    automatically: WiFi (UDP), BLE-relay (via dual-protocol neighbour),
    or BLE-direct (gateway BLE advertising).

    Request JSON: { "node_id": "NODE_01", "mode": "latency",
                    "weights": {"w_latency": 0.8, ...} }
    """
    from flask import request as _req
    body = _req.get_json(silent=True)
    if not body:
        return jsonify({"ok": False, "message": "Empty or invalid JSON body"}), 400

    node_id = body.get("node_id", "")
    mode    = body.get("mode", "balanced")
    weights = body.get("weights", {})

    if not node_id:
        return jsonify({"ok": False, "message": "node_id required"}), 400

    # Validate mode — accept both frontend and gateway naming conventions
    if mode not in WEIGHT_PROFILES:
        return jsonify({"ok": False,
                        "message": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}), 400

    # If weights not provided, use the profile defaults
    if not weights:
        weights = WEIGHT_PROFILES[mode]

    with matrix_lock:
        all_nodes = copy.deepcopy(health_matrix)

    if node_id not in all_nodes:
        return jsonify({"ok": False,
                        "message": f"Node {node_id!r} not in health matrix"}), 404

    ok, message, delivery = deliver_route_pref(node_id, mode, weights, all_nodes)
    return jsonify({
        "ok"      : ok,
        "delivery": delivery,
        "message" : message,
    })


@flask_app.route("/route_pref_batch", methods=["POST"])
def api_route_pref_batch():
    """
    Push a routing-weight update to multiple nodes at once.

    Request JSON: {
        "node_ids": ["NODE_01", "NODE_02"],
        "mode": "latency",
        "weights": {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05}
    }

    Response: {
        "mode": "latency",
        "weights": {...},
        "node_results": {
            "NODE_01": {"ok": true, "message": "...", "delivery": "UDP"},
            "NODE_02": {"ok": true, "message": "...", "delivery": "relay"}
        },
        "success_count": 2,
        "fail_count": 0
    }
    """
    from flask import request as _req
    body = _req.get_json(silent=True)
    if not body:
        return jsonify({"error": "Empty or invalid JSON body"}), 400

    node_ids = body.get("node_ids", [])
    mode     = body.get("mode", "balanced")
    weights  = body.get("weights", {})

    if not node_ids:
        return jsonify({"error": "node_ids list required"}), 400

    if mode not in WEIGHT_PROFILES:
        return jsonify({"error": f"Invalid mode. Use: {list(WEIGHT_PROFILES.keys())}"}), 400

    if not weights:
        weights = WEIGHT_PROFILES[mode]

    with matrix_lock:
        all_nodes = copy.deepcopy(health_matrix)

    results = {}
    for nid in node_ids:
        if nid not in all_nodes:
            results[nid] = {"ok": False, "message": "Node not in health matrix",
                           "delivery": "none"}
            continue
        ok, message, delivery = deliver_route_pref(nid, mode, weights, all_nodes)
        results[nid] = {"ok": ok, "message": message, "delivery": delivery}

    success_count = sum(1 for r in results.values() if r["ok"])
    fail_count    = len(results) - success_count

    return jsonify({
        "mode"         : mode,
        "weights"      : weights,
        "node_results" : results,
        "success_count": success_count,
        "fail_count"   : fail_count,
        "total_nodes"  : len(node_ids),
    })


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
            last_seq = _ble_last_seq.get(node_id)
            is_new   = (last_seq != seq)
            if is_new:
                _ble_last_seq[node_id] = seq

            if pkt_type == BLE_PKT_TYPE_METRIC:
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