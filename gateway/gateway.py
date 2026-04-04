"""
===================================================
IoT Mesh Network Gateway - Raspberry Pi 4
===================================================
Responsibilities:
  - Listen UDP ports 5006 (metrics) and 5005 (mesh/hello)
  - Maintain live Health Matrix per node
  - BLE scanner (bleak) for BLE-only node metrics
  - BLE ROUTE_PREF advertiser (btmgmt/hcitool) for BLE-only nodes
  - REST API for server.py and dashboard
  - 4-byte truncated HMAC on BLE ROUTE_PREF packets
===================================================
Requirements:
    pip install flask bleak
    sudo apt install bluez        # for btmgmt
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
import shutil
from datetime import datetime
from flask import Flask, jsonify

SHARED_KEY = b"mesh_secret_2106"

BLE_SCAN_ENABLED = True
try:
    import asyncio
    from bleak import BleakScanner
except ImportError:
    BLE_SCAN_ENABLED = False
    print("[BLE-GW] bleak not installed – BLE scanning disabled")

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
GATEWAY_LISTEN_IP   = "0.0.0.0"
GATEWAY_PORT        = 5006
MESH_PORT           = 5005
HEALTH_MATRIX_FILE  = "health_matrix.json"
FLASK_PORT          = 8080
LOG_FILE            = "gateway.log"

LATENCY_WARN_MS     = 100
LATENCY_CRIT_MS     = 300
PACKET_LOSS_WARN    = 0.05
PACKET_LOSS_CRIT    = 0.20
RSSI_WARN_DBM       = -75
RSSI_CRIT_DBM       = -85
NODE_TIMEOUT_SEC    = 60

WEIGHT_PROFILES = {
    "latency":  {"w_latency": 0.8, "w_packet_loss": 0.15, "w_power": 0.05},
    "cost":     {"w_latency": 0.3, "w_packet_loss": 0.5,  "w_power": 0.2},
    "power":    {"w_latency": 0.1, "w_packet_loss": 0.2,  "w_power": 0.7},
    "balanced": {"w_latency": 0.5, "w_packet_loss": 0.3,  "w_power": 0.2},
}

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger("gateway")
logging.getLogger("bleak").setLevel(logging.WARNING)
logging.getLogger("dbus_fast").setLevel(logging.WARNING)
logging.getLogger("bleak.backends.bluezdbus.scanner").setLevel(logging.WARNING)

# ─────────────────────────────────────────────
#  HEALTH MATRIX
# ─────────────────────────────────────────────
matrix_lock   = threading.Lock()
health_matrix = {}
seq_tracker   = {}

# ─────────────────────────────────────────────
#  BLE CONSTANTS & DECODER
# ─────────────────────────────────────────────
BLE_MAGIC               = bytes([0xAA, 0xBB])
BLE_PKT_TYPE_HELLO      = 0x01
BLE_PKT_TYPE_METRIC     = 0x02
BLE_PKT_TYPE_PING       = 0x03
BLE_PKT_TYPE_PONG       = 0x04
BLE_PKT_TYPE_ROUTE_PREF = 0x05

_ROUTE_MODE_WMAP = {"balanced": 0, "latency": 1, "cost": 2, "power": 3}

def decode_ble_payload(manuf_data):
    try:
        b = bytes(manuf_data)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None
        node_id = b[3:10].rstrip(b'\x00').decode('utf-8')
        if not node_id or not node_id.startswith("NODE_") or len(node_id) > 7:
            return None
        return {
            "pkt_type": b[2], "node_id": node_id, "seq": b[10],
            "ts": int.from_bytes(b[11:15], 'big'),
            "rssi": b[15] - 128,
            "lat_ms": ((b[16] << 8) | b[17]) / 10.0,
            "loss": b[18] / 255.0
        }
    except Exception:
        return None

def find_manuf_data_gw(adv_data_bytes):
    b = bytes(adv_data_bytes)
    idx = 0
    while idx < len(b) - 1:
        length = b[idx]
        if length == 0: break
        ad_type = b[idx + 1]
        if ad_type == 0xFF and length >= 3:
            return b[idx + 2: idx + 1 + length]
        idx += 1 + length
    return None

# ─────────────────────────────────────────────
#  HMAC HELPERS
# ─────────────────────────────────────────────
def sign_packet(pkt_dict):
    payload = json.dumps(pkt_dict).encode()
    sig = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
    pkt_dict["sig"] = sig
    return pkt_dict

def verify_packet(pkt_dict):
    sig = pkt_dict.pop("sig", None)
    if not sig: return False
    payload = json.dumps(pkt_dict).encode()
    expected = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
    return sig == expected

def verify_packet_raw(raw_bytes):
    try:
        pkt = json.loads(raw_bytes.decode('utf-8'))
        sig = pkt.pop("sig", None)
        if not sig: return False
        payload = json.dumps(pkt, sort_keys=True, separators=(',', ':')).encode()
        expected = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception as e:
        log.warning(f"[Security] verify error: {e}")
        return False

def _hmac4_gateway(key, msg):
    """4-byte truncated HMAC-SHA256 for BLE packets. Matches ble_code._hmac4."""
    return hmac.new(key, msg, hashlib.sha256).digest()[:4]

# ─────────────────────────────────────────────
#  HEALTH SCORE
# ─────────────────────────────────────────────
def compute_health_score(node_data):
    score, alerts = 100.0, []
    latency = node_data.get("avg_latency_ms", 0)
    if latency >= LATENCY_CRIT_MS: score -= 30; alerts.append(f"CRITICAL latency: {latency:.1f} ms")
    elif latency >= LATENCY_WARN_MS: score -= 15; alerts.append(f"HIGH latency: {latency:.1f} ms")
    loss = node_data.get("packet_loss", 0.0)
    if loss >= PACKET_LOSS_CRIT: score -= 30; alerts.append(f"CRITICAL packet loss: {loss*100:.1f}%")
    elif loss >= PACKET_LOSS_WARN: score -= 15; alerts.append(f"HIGH packet loss: {loss*100:.1f}%")
    rssi = node_data.get("rssi", -99)
    if rssi <= RSSI_CRIT_DBM: score -= 20; alerts.append(f"CRITICAL signal: {rssi} dBm")
    elif rssi <= RSSI_WARN_DBM: score -= 10; alerts.append(f"WEAK signal: {rssi} dBm")
    hops = node_data.get("hop_count", 0)
    if hops > 3: score -= (hops - 3) * 5; alerts.append(f"High hop count: {hops}")
    status = "ONLINE"
    if score < 40: status = "DEGRADED"
    if score <= 0 or node_data.get("status") == "OFFLINE": status = "OFFLINE"; score = 0
    return max(0.0, round(score, 1)), status, alerts

# ─────────────────────────────────────────────
#  PROCESS METRIC PACKET
# ─────────────────────────────────────────────
def process_metric_packet(pkt, sender_ip):
    node_id = pkt.get("node_id")
    if not node_id: return
    now = time.time()
    now_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    metrics = pkt.get("metrics", {})
    seq, rt, nb = pkt.get("seq_number", 0), pkt.get("routing_table", {}), pkt.get("neighbours", [])
    rssi = pkt.get("rssi", -99)
    route_mode, weights = pkt.get("route_mode"), pkt.get("weights")
    hops, protocol = pkt.get("hop_count", 0), pkt.get("protocol", "WiFi")
    latency = metrics.get("wifi_avg_latency_ms", metrics.get("ble_avg_latency_ms", 0.0))
    loss = metrics.get("wifi_packet_loss", metrics.get("ble_packet_loss", 0.0))

    with matrix_lock:
        existing = health_matrix.get(node_id, {})
        BLE_PH = ("BLE-direct", "BLE-only", "")
        relayed_by = pkt.get("relayed_by", "")
        is_relayed = bool(relayed_by and relayed_by != node_id)
        self_ip = pkt.get("ip", "")
        exist_ip = existing.get("sender_ip", "")
        exist_wip = existing.get("wifi_sender_ip", "")
        if self_ip and self_ip not in BLE_PH and self_ip != "0.0.0.0":
            resolved_ip = self_ip; wifi_sender_ip = self_ip
        elif not is_relayed and sender_ip not in BLE_PH:
            resolved_ip = sender_ip; wifi_sender_ip = sender_ip
        elif exist_ip and exist_ip not in BLE_PH:
            resolved_ip = exist_ip; wifi_sender_ip = exist_wip if exist_wip not in BLE_PH else exist_ip
        else:
            resolved_ip = sender_ip if sender_ip not in BLE_PH else "BLE-only"
            wifi_sender_ip = exist_wip if exist_wip not in BLE_PH else ""
        sender_ip = resolved_ip

        seq_key = (node_id, protocol)
        if seq_key not in seq_tracker:
            seq_tracker[seq_key] = {"last_seq": seq, "expected_seq": seq + 1, "total_received": 1, "total_lost": 0}
        else:
            st = seq_tracker[seq_key]; gap = seq - st["last_seq"] - 1
            if gap > 0: st["total_lost"] += gap
            st["total_received"] += 1; st["last_seq"] = seq; st["expected_seq"] = seq + 1
        st = seq_tracker[seq_key]
        total_rx, total_lost = st["total_received"], st["total_lost"]
        real_loss = total_lost / (total_rx + total_lost) if (total_rx + total_lost) > 0 else 0.0

        lat_hist = existing.get("latency_history", []); rssi_hist = existing.get("rssi_history", [])
        lat_hist.append(latency); rssi_hist.append(rssi)
        if len(lat_hist) > 20: lat_hist.pop(0)
        if len(rssi_hist) > 20: rssi_hist.pop(0)

        node_data = {
            "node_id": node_id, "protocol": protocol, "sender_ip": sender_ip,
            "wifi_sender_ip": wifi_sender_ip, "last_seen": now, "last_seen_str": now_str,
            "rssi": rssi, "avg_latency_ms": latency, "packet_loss": round(real_loss, 4),
            "throughput_est": 0.0, "hop_count": hops, "seq_last": seq, "seq_expected": seq + 1,
            "packets_received": total_rx, "packets_lost": total_lost,
            "neighbours": nb, "routing_table": rt,
            "latency_history": lat_hist, "rssi_history": rssi_hist,
            "metrics": metrics,
            "route_mode": route_mode or existing.get("route_mode", "balanced"),
            "route_weights": weights or existing.get("route_weights", {}),
            "route_ack_time": existing.get("route_ack_time"),
        }
        score, status, alerts = compute_health_score(node_data)
        node_data["health_score"] = score; node_data["status"] = status; node_data["alerts"] = alerts
        health_matrix[node_id] = node_data
    log.info(f"[{node_id}] Proto={protocol} Seq={seq} RSSI={rssi} Lat={latency:.1f}ms Loss={real_loss*100:.1f}% Score={score}")

def process_hello_packet(pkt, sender_ip):
    node_id = pkt.get("node_id")
    if not node_id: return
    now, rssi, rt = time.time(), pkt.get("rssi", -99), pkt.get("routing", {})
    with matrix_lock:
        if node_id not in health_matrix:
            health_matrix[node_id] = {
                "node_id": node_id, "protocol": pkt.get("protocol", "WiFi"),
                "status": "ONLINE", "health_score": 100.0, "last_seen": now,
                "last_seen_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                "rssi": rssi, "avg_latency_ms": 0.0, "packet_loss": 0.0,
                "routing_table": rt, "sender_ip": sender_ip,
                "alerts": [], "packets_received": 0, "packets_lost": 0, "metrics": {},
            }
        else:
            h = health_matrix[node_id]
            h["last_seen"] = now; h["last_seen_str"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            h["rssi"] = rssi; h["routing_table"] = rt
            h["protocol"] = pkt.get("protocol", h.get("protocol", "WiFi"))
            h["sender_ip"] = sender_ip

def process_route_pref_ack(pkt, sender_ip):
    node_id = pkt.get("node_id")
    if not node_id: return
    mode = pkt.get("mode", "balanced")
    weights = {"w_latency": pkt.get("w_latency"), "w_packet_loss": pkt.get("w_packet_loss"), "w_power": pkt.get("w_power")}
    delivery, relayed_by, relay_ok = pkt.get("delivery", "UDP"), pkt.get("relayed_by", ""), pkt.get("relay_ok", True)
    now = time.time()
    with matrix_lock:
        if node_id in health_matrix:
            health_matrix[node_id]["route_mode"] = mode
            health_matrix[node_id]["route_weights"] = weights
            if relay_ok:
                health_matrix[node_id]["route_ack_time"] = now
            if sender_ip not in ("BLE-direct", "BLE-only", "") and not relayed_by:
                health_matrix[node_id]["sender_ip"] = sender_ip
                health_matrix[node_id]["wifi_sender_ip"] = sender_ip
    via = f" via relay {relayed_by}" if relayed_by else ""
    log.info(f"[RoutePref] ACK from {node_id}{via}: mode={mode} delivery={delivery} L={weights['w_latency']} P={weights['w_packet_loss']} W={weights['w_power']}")

# ─────────────────────────────────────────────
#  BACKGROUND LOOPS
# ─────────────────────────────────────────────
def watchdog_loop():
    while True:
        now = time.time()
        with matrix_lock:
            for nid, d in health_matrix.items():
                age = now - d.get("last_seen", now)
                if age > NODE_TIMEOUT_SEC and d.get("status") != "OFFLINE":
                    health_matrix[nid]["status"] = "OFFLINE"; health_matrix[nid]["health_score"] = 0
                    health_matrix[nid]["alerts"] = [f"Node silent for {int(age)}s"]
        time.sleep(10)

def persist_loop():
    while True:
        with matrix_lock:
            snapshot = {"gateway_timestamp": time.time(), "gateway_time_str": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "node_count": len(health_matrix), "nodes": copy.deepcopy(health_matrix)}
        with open(HEALTH_MATRIX_FILE, "w") as f: json.dump(snapshot, f, indent=2)
        time.sleep(5)

def print_dashboard():
    os.system('clear' if os.name == 'posix' else 'cls')
    with matrix_lock: nodes = dict(health_matrix)
    print(f"  IoT Mesh Gateway  |  {datetime.now().strftime('%H:%M:%S')}  |  Nodes: {len(nodes)}")
    print("  " + "─" * 76)
    for nid, d in sorted(nodes.items()):
        s = d.get("status","?"); sc = d.get("health_score",0); ip = d.get("sender_ip","?")
        rm = d.get("route_mode","?")
        print(f"  {nid:<12} {s:<10} score={sc:<4} rssi={d.get('rssi',-99):<6} mode={rm:<10} {ip}")
    print("  " + "─" * 76)

def dashboard_loop():
    while True: print_dashboard(); time.sleep(5)

# ─────────────────────────────────────────────
#  UDP LISTENERS
# ─────────────────────────────────────────────
def udp_metric_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((GATEWAY_LISTEN_IP, GATEWAY_PORT))
    while True:
        try:
            raw, addr = sock.recvfrom(4096)
            if not verify_packet_raw(raw): continue
            pkt = json.loads(raw.decode('utf-8')); pkt.pop("sig", None)
            ptype = pkt.get("type")
            if ptype == "METRIC": process_metric_packet(pkt, addr[0])
            elif ptype == "HELLO": process_hello_packet(pkt, addr[0])
        except Exception as e: log.error(f"[UDP] Metric error: {e}")

def udp_mesh_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((GATEWAY_LISTEN_IP, MESH_PORT))
    log.info(f"[UDP] Mesh listener on port {MESH_PORT}")
    while True:
        try:
            raw, addr = sock.recvfrom(4096)
            if not verify_packet_raw(raw): continue
            pkt = json.loads(raw.decode('utf-8')); pkt.pop("sig", None)
            ptype = pkt.get("type")
            if ptype == "HELLO": process_hello_packet(pkt, addr[0])
            elif ptype == "ROUTE_PREF_ACK": process_route_pref_ack(pkt, addr[0])
        except Exception as e: log.error(f"[UDP] Mesh error: {e}")

# ─────────────────────────────────────────────
#  GATEWAY BLE ROUTE_PREF ADVERTISING
#  Tries btmgmt first (modern BlueZ), falls back to hcitool.
#  Includes 4-byte truncated HMAC matching ble_code.py.
# ─────────────────────────────────────────────

_gw_ble_route_pref_seq = 0
_gw_ble_adv_lock = threading.Lock()

# Detect which BLE advertising tool is available (checked once at startup)
_ble_adv_tool = None

def _detect_ble_adv_tool():
    """Detect available BLE advertising tool. Called once."""
    global _ble_adv_tool
    if shutil.which("btmgmt"):
        _ble_adv_tool = "btmgmt"
    elif shutil.which("hcitool"):
        _ble_adv_tool = "hcitool"
    else:
        _ble_adv_tool = None
    log.info(f"[BLE-GW] Advertising tool: {_ble_adv_tool or 'NONE — install bluez'}")

def _encode_route_pref_ble(target_node_id, w_latency, w_packet_loss,
                           w_power, mode, seq):
    """Encode 19-byte ROUTE_PREF with 4-byte truncated HMAC."""
    raw_b = target_node_id.encode()[:7]
    node_b = raw_b + b'\x00' * (7 - len(raw_b))
    mode_byte = _ROUTE_MODE_WMAP.get(mode, 0)
    data_15 = (BLE_MAGIC
               + bytes([BLE_PKT_TYPE_ROUTE_PREF])
               + node_b
               + bytes([
                   min(255, int(w_latency * 200)),
                   min(255, int(w_packet_loss * 200)),
                   min(255, int(w_power * 200)),
                   mode_byte,
                   seq & 0xFF,
               ]))
    mac4 = _hmac4_gateway(SHARED_KEY, data_15)
    return data_15 + mac4


def _ble_advertise_btmgmt(ad_hex, duration_s):
    """Advertise using btmgmt (modern BlueZ 5.56+)."""
    try:
        # Register advertisement with manufacturer data
        cmd_add = ['sudo', 'btmgmt', '-i', 'hci0', 'add-adv',
                   '-d', ad_hex, '1']
        result = subprocess.run(cmd_add, timeout=3, capture_output=True)
        if result.returncode != 0:
            err = result.stderr.decode().strip()
            return False, f"btmgmt add-adv failed: {err}"
        time.sleep(duration_s)
        # Remove advertisement
        subprocess.run(['sudo', 'btmgmt', '-i', 'hci0', 'rm-adv', '1'],
                      timeout=2, capture_output=True)
        return True, "btmgmt"
    except FileNotFoundError:
        return False, "btmgmt not found"
    except subprocess.TimeoutExpired:
        return False, "btmgmt timed out"
    except Exception as e:
        return False, str(e)


def _ble_advertise_hcitool(ad_bytes, duration_s):
    """Advertise using hcitool (legacy BlueZ)."""
    try:
        ad_len = len(ad_bytes)
        hex_args = [f'{ad_len:02X}'] + [f'{b:02X}' for b in ad_bytes]
        while len(hex_args) < 32:
            hex_args.append('00')
        # Set advertising data
        cmd_set = ['sudo', 'hcitool', '-i', 'hci0', 'cmd', '0x08', '0x0008'] + hex_args
        result = subprocess.run(cmd_set, timeout=2, capture_output=True)
        if result.returncode != 0:
            return False, f"hcitool set-adv failed: {result.stderr.decode().strip()}"
        # Enable advertising
        subprocess.run(['sudo', 'hcitool', '-i', 'hci0', 'cmd', '0x08', '0x000A', '01'],
                      timeout=2, capture_output=True)
        time.sleep(duration_s)
        # Disable
        subprocess.run(['sudo', 'hcitool', '-i', 'hci0', 'cmd', '0x08', '0x000A', '00'],
                      timeout=2, capture_output=True)
        return True, "hcitool"
    except FileNotFoundError:
        return False, "hcitool not found"
    except subprocess.TimeoutExpired:
        return False, "hcitool timed out"
    except Exception as e:
        return False, str(e)


def gateway_ble_advertise_route_pref(target_node_id, w_latency, w_packet_loss,
                                     w_power, mode, duration_s=1.5):
    """
    BLE-advertise a ROUTE_PREF from the Raspberry Pi gateway.
    Tries btmgmt first, falls back to hcitool. Duration reduced
    to 1.5s to support multiple BLE nodes in a batch without timeout.
    """
    global _gw_ble_route_pref_seq

    if not BLE_SCAN_ENABLED:
        return False, "BLE not available (bleak not installed)"

    if _ble_adv_tool is None:
        return False, ("No BLE advertising tool found. Run: sudo apt install bluez\n"
                       "Then run gateway with: sudo python3 gatewayv3.py")

    with _gw_ble_adv_lock:
        try:
            _gw_ble_route_pref_seq = (_gw_ble_route_pref_seq + 1) & 0xFF
            payload = _encode_route_pref_ble(
                target_node_id, w_latency, w_packet_loss, w_power,
                mode, _gw_ble_route_pref_seq)

            ad = bytes([len(payload) + 1, 0xFF]) + payload
            ad_hex = ad.hex()

            ok, tool = False, ""
            if _ble_adv_tool == "btmgmt":
                ok, tool = _ble_advertise_btmgmt(ad_hex, duration_s)
                if not ok:
                    log.warning(f"[BLE-GW] btmgmt failed ({tool}), trying hcitool...")
                    ok, tool = _ble_advertise_hcitool(ad, duration_s)
            else:
                ok, tool = _ble_advertise_hcitool(ad, duration_s)

            if ok:
                log.info(f"[BLE-GW] ROUTE_PREF advertised for {target_node_id}: "
                         f"mode={mode} seq={_gw_ble_route_pref_seq} via {tool} "
                         f"({duration_s}s) HMAC=yes")
                return True, f"BLE ROUTE_PREF advertised for {target_node_id} via {tool}"
            else:
                msg = (f"BLE advertising failed for {target_node_id}: {tool}. "
                       f"Ensure: (1) sudo python3 gatewayv3.py, "
                       f"(2) sudo apt install bluez, "
                       f"(3) sudo systemctl start bluetooth")
                log.error(f"[BLE-GW] {msg}")
                return False, msg

        except Exception as e:
            msg = f"BLE advertising error: {e}"
            log.error(f"[BLE-GW] {msg}")
            return False, msg

# ─────────────────────────────────────────────
#  ROUTE PREF DELIVERY
# ─────────────────────────────────────────────
BLE_ONLY_VALUES = {"BLE-direct", "BLE-only", ""}

def _best_ip(nd):
    for field in ("wifi_sender_ip", "sender_ip"):
        ip = nd.get(field, "")
        if ip and ip not in BLE_ONLY_VALUES: return ip
    return ""

def deliver_route_pref(node_id, mode, weights, all_nodes):
    """Deliver ROUTE_PREF via: 1) UDP direct, 2) relay, 3) BLE direct."""
    node_data = all_nodes.get(node_id)
    if not node_data:
        return False, f"Node {node_id!r} not in health matrix", "none"

    def _build_signed_pkt(target):
        pkt = {"type": "ROUTE_PREF", "node_id": "GATEWAY", "target": target,
               "mode": mode, "w_latency": weights.get("w_latency", 0.5),
               "w_packet_loss": weights.get("w_packet_loss", 0.3),
               "w_power": weights.get("w_power", 0.2), "timestamp": int(time.time())}
        payload = json.dumps(pkt, sort_keys=True, separators=(',', ':')).encode()
        pkt["sig"] = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
        return pkt

    def _udp_send(ip, pkt):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
            s.sendto(json.dumps(pkt).encode(), (ip, MESH_PORT)); s.close()
            return True, f"sent to {ip}"
        except Exception as e: return False, str(e)

    # Method 1: Direct UDP
    target_ip = _best_ip(node_data)
    if target_ip:
        pkt = _build_signed_pkt(node_id)
        ok, detail = _udp_send(target_ip, pkt)
        if ok:
            log.info(f"[RoutePref] UDP → {node_id} @ {target_ip}  mode={mode}")
            return True, f"ROUTE_PREF sent to {node_id} @ {target_ip}", "UDP"
        log.warning(f"[RoutePref] UDP failed for {node_id}: {detail}")

    # Method 2: Relay via dual-protocol neighbour
    relay_ip, relay_name = "", ""
    for nid, nd in all_nodes.items():
        if nid == node_id: continue
        if _best_ip(nd) and node_id in nd.get("neighbours", []):
            relay_ip = _best_ip(nd); relay_name = nid; break
    if relay_ip:
        pkt = _build_signed_pkt(node_id)
        ok, detail = _udp_send(relay_ip, pkt)
        if ok:
            log.info(f"[RoutePref] Relay → {node_id} via {relay_name} @ {relay_ip}  mode={mode}")
            return True, f"Sent via relay {relay_name}", "relay"
        log.warning(f"[RoutePref] Relay failed: {detail}")

    # Method 3: Direct BLE from gateway
    if BLE_SCAN_ENABLED:
        ok, msg = gateway_ble_advertise_route_pref(
            node_id, weights.get("w_latency", 0.5),
            weights.get("w_packet_loss", 0.3), weights.get("w_power", 0.2), mode)
        if ok:
            return True, msg, "BLE-direct"
        log.warning(f"[RoutePref] BLE-direct failed: {msg}")

    return False, f"No delivery path for {node_id} — tried UDP, relay, BLE", "none"

# ─────────────────────────────────────────────
#  FLASK REST API
# ─────────────────────────────────────────────
flask_app = Flask(__name__)

@flask_app.route("/health_matrix", methods=["GET"])
def api_health_matrix():
    with matrix_lock:
        data = {"gateway_timestamp": time.time(), "gateway_time_str": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "node_count": len(health_matrix), "nodes": copy.deepcopy(health_matrix)}
    return jsonify(data)

@flask_app.route("/node/<node_id>", methods=["GET"])
def api_node(node_id):
    with matrix_lock:
        n = copy.deepcopy(health_matrix.get(node_id))
    return jsonify(n) if n else (jsonify({"error": "Node not found"}), 404)

@flask_app.route("/summary", methods=["GET"])
def api_summary():
    with matrix_lock:
        summary = {nid: {"status": d.get("status"), "health_score": d.get("health_score"),
                         "rssi": d.get("rssi"), "avg_latency": d.get("avg_latency_ms"),
                         "packet_loss": d.get("packet_loss"), "last_seen": d.get("last_seen_str")}
                   for nid, d in health_matrix.items()}
    return jsonify({"node_count": len(summary), "nodes": summary, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@flask_app.route("/topology", methods=["GET"])
def api_topology():
    edges = []
    with matrix_lock:
        for nid, d in health_matrix.items():
            for nb in d.get("neighbours", []): edges.append({"from": nid, "to": nb})
            for dest, route in d.get("routing_table", {}).items():
                edges.append({"from": nid, "to": dest, "via": route.get("next_hop"),
                              "hop_count": route.get("hop_count"), "latency": route.get("avg_latency_ms"),
                              "cost": route.get("cost"), "protocol": route.get("best_protocol")})
    return jsonify({"edges": edges})

@flask_app.route("/ping", methods=["GET"])
def api_ping():
    return jsonify({"status": "ok", "gateway": "running", "ble_adv_tool": _ble_adv_tool or "none"})

@flask_app.route("/route_pref", methods=["POST"])
def api_route_pref():
    from flask import request as _req
    body = _req.get_json(silent=True)
    if not body: return jsonify({"ok": False, "message": "Empty JSON"}), 400
    node_id, mode = body.get("node_id", ""), body.get("mode", "balanced")
    weights = body.get("weights", {})
    if not node_id: return jsonify({"ok": False, "message": "node_id required"}), 400
    if mode not in WEIGHT_PROFILES: return jsonify({"ok": False, "message": f"Invalid mode"}), 400
    if not weights: weights = WEIGHT_PROFILES[mode]
    with matrix_lock: all_nodes = copy.deepcopy(health_matrix)
    if node_id not in all_nodes: return jsonify({"ok": False, "message": f"Node {node_id!r} not found"}), 404
    ok, msg, delivery = deliver_route_pref(node_id, mode, weights, all_nodes)
    return jsonify({"ok": ok, "delivery": delivery, "message": msg})

@flask_app.route("/route_pref_batch", methods=["POST"])
def api_route_pref_batch():
    from flask import request as _req
    body = _req.get_json(silent=True)
    if not body: return jsonify({"error": "Empty JSON"}), 400
    node_ids, mode = body.get("node_ids", []), body.get("mode", "balanced")
    weights = body.get("weights", {})
    if not node_ids: return jsonify({"error": "node_ids required"}), 400
    if mode not in WEIGHT_PROFILES: return jsonify({"error": "Invalid mode"}), 400
    if not weights: weights = WEIGHT_PROFILES[mode]
    with matrix_lock: all_nodes = copy.deepcopy(health_matrix)
    results = {}
    for nid in node_ids:
        if nid not in all_nodes:
            results[nid] = {"ok": False, "message": "Not in health matrix", "delivery": "none"}; continue
        ok, msg, delivery = deliver_route_pref(nid, mode, weights, all_nodes)
        results[nid] = {"ok": ok, "message": msg, "delivery": delivery}
    sc = sum(1 for r in results.values() if r["ok"])
    return jsonify({"mode": mode, "weights": weights, "node_results": results,
                    "success_count": sc, "fail_count": len(results) - sc, "total_nodes": len(node_ids)})

def run_flask():
    flask_app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, use_reloader=False)

# ─────────────────────────────────────────────
#  BLE GATEWAY SCANNER
# ─────────────────────────────────────────────
_ble_last_seq = {}

def ble_advertisement_callback(device, advertisement_data):
    try:
        manuf = advertisement_data.manufacturer_data
        if not manuf: return
        for company_id, payload in manuf.items():
            full = bytes([company_id & 0xFF, (company_id >> 8) & 0xFF]) + bytes(payload)
            decoded = decode_ble_payload(full) or decode_ble_payload(bytes(payload))
            if not decoded: continue
            node_id, pkt_type = decoded["node_id"], decoded["pkt_type"]
            adv_rssi, seq = advertisement_data.rssi or -99, decoded["seq"]
            is_new = (_ble_last_seq.get(node_id) != seq)
            if is_new: _ble_last_seq[node_id] = seq
            if pkt_type == BLE_PKT_TYPE_METRIC and is_new:
                pkt = {"type": "METRIC", "node_id": node_id, "protocol": "BLE-Direct",
                       "timestamp": time.time(), "seq_number": seq, "hop_count": 0,
                       "rssi": adv_rssi, "ip": "BLE-only", "neighbours": [], "routing_table": {},
                       "metrics": {"wifi_avg_latency_ms": 0, "ble_avg_latency_ms": decoded["lat_ms"],
                                   "wifi_packet_loss": 1.0, "ble_packet_loss": decoded["loss"],
                                   "wifi_rssi": -99, "ble_rssi": adv_rssi}}
                process_metric_packet(pkt, "BLE-direct")
                log.info(f"[BLE-GW] Metric from {node_id} RSSI={adv_rssi} seq={seq}")
            elif pkt_type == BLE_PKT_TYPE_HELLO and is_new:
                process_hello_packet({"type": "HELLO", "node_id": node_id,
                                      "protocol": "BLE-Direct", "rssi": adv_rssi, "routing": {}}, "BLE-direct")
    except Exception as e:
        log.debug(f"[BLE-GW] Callback error: {e}")

async def ble_scan_async():
    log.info("[BLE-GW] Starting BLE scanner...")
    try:
        scanner = BleakScanner(detection_callback=ble_advertisement_callback)
        await scanner.start()
        log.info("[BLE-GW] BLE scanner active")
        while True: await asyncio.sleep(1)
    except Exception as e:
        log.error(f"[BLE-GW] Scanner error: {e}")

def ble_gateway_scanner():
    if not BLE_SCAN_ENABLED: return
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    try: loop.run_until_complete(ble_scan_async())
    except Exception as e: log.error(f"[BLE-GW] Fatal: {e}")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  IoT Mesh Gateway  –  Raspberry Pi 4")
    print("=" * 60)
    _detect_ble_adv_tool()

    threads = [
        threading.Thread(target=udp_metric_listener, daemon=True, name="MetricListener"),
        threading.Thread(target=udp_mesh_listener, daemon=True, name="MeshListener"),
        threading.Thread(target=watchdog_loop, daemon=True, name="Watchdog"),
        threading.Thread(target=persist_loop, daemon=True, name="Persist"),
        threading.Thread(target=dashboard_loop, daemon=True, name="Dashboard"),
        threading.Thread(target=run_flask, daemon=True, name="Flask"),
        threading.Thread(target=ble_gateway_scanner, daemon=True, name="BLE-Scanner"),
    ]
    for t in threads: t.start(); log.info(f"  Started: {t.name}")
    log.info("Gateway operational.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")

if __name__ == "__main__":
    main()