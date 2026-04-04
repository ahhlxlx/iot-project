"""
╔══════════════════════════════════════════════════════════════════╗
║  node_main.py  –  IoT Mesh Network Node  (Maker Pi Pico W)      ║
║  Dual-Protocol: WiFi  +  BLE  (both carry real data)            ║
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
╠══════════════════════════════════════════════════════════════════╣
║  Module layout:                                                  ║
║   ble_code.py   – BLE hardware: encode/decode, advertise, IRQ   ║
║   wifi_code.py  – WiFi hardware: connect, UDP socket, send      ║
║   node_main.py  – Routing, processing, orchestration, main loop ║
╚══════════════════════════════════════════════════════════════════╝

MicroPython v1.22+ required  (network + ubluetooth modules)
Upload ble_code.py, wifi_code.py and node_main.py (rename to main.py)
to Pico W to auto-start on boot.
"""

import time
import json
import hashlib
import machine
import sys
sys.path.append('/Project')

import ble_code
import wifi_code

# Re-export BLE packet type constants for use in this module
from ble_code import (
    BLE_PKT_TYPE_HELLO, BLE_PKT_TYPE_METRIC,
    BLE_PKT_TYPE_PING,  BLE_PKT_TYPE_PONG,
)

# ══════════════════════════════════════════════
#  ① NODE CONFIGURATION  ← edit per device
# ══════════════════════════════════════════════

NODE_ID       = "NODE_lx"             # Change to NODE_02, NODE_03 … for each Pico W
GATEWAY_IP    = "10.202.64.140"        # Raspberry Pi IP
WIFI_SSID     = "OnePlus13Equals14"   # Shared WiFi network name
WIFI_PASSWORD = "gkpm5847"            # Shared WiFi password

ENABLE_WIFI = False
ENABLE_BLE  = True

# Cost-function weights  (must sum to 1.0)
# Updated at runtime via ROUTE_PREF packets from the dashboard
W_LATENCY     = 0.5    # Higher = prioritise low latency
W_PACKET_LOSS = 0.3    # Higher = prioritise reliability
W_POWER       = 0.2    # Higher = prioritise battery saving
route_mode    = "balanced"   # Current optimisation mode name

# Timing (seconds)
HELLO_INTERVAL  = 5    # Neighbour discovery broadcast interval
METRIC_INTERVAL = 10   # How often to send metrics to gateway
PING_INTERVAL   = 8    # How often to probe neighbour RTT
ROUTE_TIMEOUT   = 45   # Drop neighbour if silent for this long

# Ports
UDP_MESH_PORT = 5005   # Node-to-node mesh communication
UDP_GW_PORT   = 5006   # Node-to-gateway data delivery

SHARED_KEY = b"mesh_secret_2106"

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

seq_number  = 0

# Pending PING timestamps: { (node_id, protocol): sent_time_ticks_ms }
ping_pending = {}

last_hello_time  = 0
last_metric_time = 0
last_ping_time   = 0


# ══════════════════════════════════════════════
#  CRYPTO HELPERS  (pure MicroPython HMAC-SHA256)
# ══════════════════════════════════════════════

def _hmac_sha256(key, msg):
    """Pure MicroPython HMAC-SHA256 implementation."""
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key  = key + b'\x00' * (block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()


def _hexdigest(b):
    """Convert bytes → hex string (MicroPython lacks .hexdigest() on raw bytes)."""
    return ''.join('{:02x}'.format(x) for x in b)


def _sorted_json(obj):
    """
    Produce a deterministic JSON string (keys sorted) for HMAC signing.
    Mirrors CPython json.dumps behaviour close enough for verification.
    """
    if isinstance(obj, dict):
        items = ['"{}":{}'.format(k, _sorted_json(obj[k])) for k in sorted(obj.keys())]
        return '{' + ','.join(items) + '}'
    elif isinstance(obj, list):
        return '[' + ','.join(_sorted_json(i) for i in obj) + ']'
    elif isinstance(obj, str):
        s = obj.replace('\\', '\\\\').replace('"', '\\"')
        s = s.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        return '"' + s + '"'
    elif isinstance(obj, bool):
        return 'true' if obj else 'false'
    elif obj is None:
        return 'null'
    elif isinstance(obj, float):
        if obj != obj:
            return 'null'
        if obj == float('inf') or obj == float('-inf'):
            return 'null'
        if obj == int(obj) and abs(obj) < 1e15:
            return '{:.1f}'.format(obj)
        formatted = '{:.10g}'.format(obj)
        if '.' not in formatted and 'e' not in formatted:
            formatted += '.0'
        return formatted
    elif isinstance(obj, int):
        return str(obj)
    else:
        return 'null'


def sign_packet(pkt_dict):
    """Attach an HMAC-SHA256 signature to pkt_dict (mutates in-place). Returns pkt_dict."""
    pkt_dict.pop("sig", None)
    payload = _sorted_json(pkt_dict).encode()
    pkt_dict["sig"] = _hexdigest(_hmac_sha256(SHARED_KEY, payload))
    return pkt_dict


def verify_packet(pkt_dict):
    """
    Verify and pop the 'sig' field from pkt_dict.
    Returns True if signature is valid, False otherwise.
    """
    sig = pkt_dict.pop("sig", None)
    if not sig:
        print(f"[HMAC] Missing sig! pkt keys={list(pkt_dict.keys())}")
        return False
    payload  = _sorted_json(pkt_dict).encode()
    expected = _hexdigest(_hmac_sha256(SHARED_KEY, payload))
    if sig != expected:
        print(f"[HMAC] FAIL sig={sig[:16]} exp={expected[:16]}")
        print(f"[HMAC] payload={payload[:80]}")
    return sig == expected


# ══════════════════════════════════════════════
#  LINK STATS HELPERS
# ══════════════════════════════════════════════

def get_link(node_id, protocol):
    """Return (and lazily create) the link-stats dict for (node_id, protocol)."""
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
            "power_cost"      : 1.0,
        }
    return link_stats[key]


def record_latency(node_id, protocol, rtt_ms, rssi):
    """
    Record a new RTT sample for the given link.
    Keeps a rolling window of 10 samples.
    Updates RSSI, last_seen, recv_count, packet_loss, and power_cost.
    """
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
    # Power cost: weaker RSSI → more TX power needed
    # -50 dBm (strong) → 0.05,  -90 dBm (weak) → 1.0
    lnk["power_cost"] = min(1.0, max(0.05, (-rssi - 50) / 40.0))


def avg_latency(node_id, protocol):
    """Return mean latency for a link, or 9999.0 if no samples exist."""
    samples = get_link(node_id, protocol)["latency_samples"]
    return sum(samples) / len(samples) if samples else 9999.0


# ══════════════════════════════════════════════
#  COST FUNCTION
# ══════════════════════════════════════════════

def compute_cost(latency_ms, packet_loss, power_cost):
    """
    Weighted path cost.  Lower = better.

      latency_ms  : average RTT in ms  (normalised /100 so 100 ms → weight 1.0)
      packet_loss : 0.0 – 1.0
      power_cost  : 0.0 – 1.0

    Example:
      WiFi: 0.5*(14/100) + 0.3*0.01 + 0.2*0.15 = 0.07 + 0.003 + 0.03 = 0.103
      BLE:  0.5*(45/100) + 0.3*0.02 + 0.2*0.40 = 0.225+ 0.006 + 0.08 = 0.311
      → WiFi wins
    """
    return (W_LATENCY     * (latency_ms / 100.0)
            + W_PACKET_LOSS * packet_loss
            + W_POWER       * power_cost)


# ══════════════════════════════════════════════
#  ROUTING TABLE  –  rebuild from link_stats
# ══════════════════════════════════════════════

def rebuild_routing_table():
    """
    For every direct neighbour compare WiFi cost vs BLE cost.
    Elects the lower-cost protocol as best_protocol for that link.
    Called after every new latency / RSSI measurement.
    """
    now = time.time()
    seen_nodes = set(n for (n, _) in link_stats.keys())

    for node_id in seen_nodes:
        wifi_lnk = get_link(node_id, "WiFi")
        ble_lnk  = get_link(node_id, "BLE")

        wifi_fresh = now - wifi_lnk["last_seen"] < ROUTE_TIMEOUT
        ble_fresh  = now - ble_lnk["last_seen"]  < ROUTE_TIMEOUT

        if not wifi_fresh and not ble_fresh:
            continue   # stale node – will be pruned

        # Per-protocol costs
        wifi_lat = avg_latency(node_id, "WiFi")

        # BLE is one-way broadcast so RTT is not directly measurable.
        # Estimate from RSSI when no samples exist:
        #   -40 dBm (strong) → ~25 ms,  -80 dBm (weak) → ~80 ms
        ble_rssi = ble_lnk["rssi"]
        if ble_lnk["latency_samples"]:
            ble_lat = avg_latency(node_id, "BLE")
        elif ble_rssi > -99:
            ble_lat = max(20.0, min(120.0, (ble_rssi + 40) * -1.375 + 25))
        else:
            ble_lat = 9999.0

        wifi_cost = (compute_cost(wifi_lat, wifi_lnk["packet_loss"], wifi_lnk["power_cost"])
                     if wifi_fresh else 9999)
        ble_cost  = (compute_cost(ble_lat,  ble_lnk["packet_loss"],  ble_lnk["power_cost"])
                     if ble_fresh  else 9999)

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
            "avg_latency_ms": round(best_lat,   2) if best_lat  < 9999 else 0,
            "packet_loss"   : round(best_loss,  4),
            "power_cost"    : round(best_power, 4),
            "cost"          : round(best_cost,  6),
            "wifi_cost"     : round(wifi_cost,  6) if wifi_fresh else None,
            "ble_cost"      : round(ble_cost,   6) if ble_fresh  else None,
            "wifi_lat"      : round(wifi_lat,   2) if wifi_fresh else None,
            "ble_lat"       : round(ble_lat,    2) if ble_fresh  else None,
            "last_seen"     : now,
        }


def learn_indirect_routes(sender_id, sender_routing, my_cost_to_sender):
    """
    Distance-vector route learning.

    If sender knows a route to node X, we can reach X by going via
    sender (one extra hop).  Only accepted when cheaper than any
    existing route to X.

    The elected best_protocol reflects the FIRST HOP from this node
    (i.e. how we reach sender_id), not the downstream protocol the
    sender uses to reach the destination.

    Args:
        sender_id        : NODE_ID of the node whose routing table we received
        sender_routing   : dict from the HELLO packet's "routing" field
        my_cost_to_sender: our current cost to sender_id (used as fallback)
    """
    for dest, info in sender_routing.items():
        if dest == NODE_ID:
            continue
        if not ble_code.valid_node_id(dest):
            continue   # reject rogue / foreign node IDs from other teams

        new_hops = info.get("hop_count", 99) + 1
        new_lat  = info.get("avg_latency_ms", 9999) + avg_latency(sender_id, "WiFi")
        new_loss = max(info.get("packet_loss", 0), get_link(sender_id, "WiFi")["packet_loss"])
        new_cost = compute_cost(new_lat, new_loss, 0.5)

        existing = routing_table.get(dest)
        if existing is None or new_cost < existing.get("cost", 9999):
            # Determine which protocol THIS node uses to reach sender_id
            sender_wifi_lnk = link_stats.get((sender_id, "WiFi"))
            sender_ble_lnk  = link_stats.get((sender_id, "BLE"))
            now_t = time.time()

            wifi_first_cost = None
            ble_first_cost  = None
            wifi_first_lat  = None
            ble_first_lat   = None

            if sender_wifi_lnk and (now_t - sender_wifi_lnk["last_seen"] < ROUTE_TIMEOUT):
                w_lat           = avg_latency(sender_id, "WiFi") + info.get("avg_latency_ms", 9999)
                wifi_first_cost = compute_cost(w_lat, sender_wifi_lnk["packet_loss"],
                                               sender_wifi_lnk["power_cost"])
                wifi_first_lat  = w_lat

            if sender_ble_lnk and (now_t - sender_ble_lnk["last_seen"] < ROUTE_TIMEOUT):
                b_lat          = avg_latency(sender_id, "BLE") + info.get("avg_latency_ms", 9999)
                ble_first_cost = compute_cost(b_lat, sender_ble_lnk["packet_loss"],
                                              sender_ble_lnk["power_cost"])
                ble_first_lat  = b_lat

            # Elect best first-hop protocol
            if (wifi_first_cost is not None
                    and (ble_first_cost is None or wifi_first_cost <= ble_first_cost)):
                my_proto_to_sender = "WiFi"
                best_indirect_cost = wifi_first_cost
                best_indirect_lat  = wifi_first_lat
            elif ble_first_cost is not None:
                my_proto_to_sender = "BLE"
                best_indirect_cost = ble_first_cost
                best_indirect_lat  = ble_first_lat
            else:
                # Fallback: no fresh direct link stats yet
                my_proto_to_sender = routing_table.get(sender_id, {}).get("best_protocol", "WiFi")
                best_indirect_cost = new_cost
                best_indirect_lat  = new_lat

            routing_table[dest] = {
                "next_hop"      : sender_id,
                "best_protocol" : my_proto_to_sender,   # ← first-hop protocol
                "hop_count"     : new_hops,
                "avg_latency_ms": round(best_indirect_lat,  2),
                "packet_loss"   : round(new_loss,           4),
                "power_cost"    : 0.5,
                "cost"          : round(best_indirect_cost, 6),
                "wifi_cost"     : round(wifi_first_cost, 6) if wifi_first_cost is not None else None,
                "ble_cost"      : round(ble_first_cost,  6) if ble_first_cost  is not None else None,
                "wifi_lat"      : round(wifi_first_lat,  2) if wifi_first_lat  is not None else None,
                "ble_lat"       : round(ble_first_lat,   2) if ble_first_lat   is not None else None,
                "last_seen"     : time.time(),
            }
            print(f"[Route] Indirect route: {dest} via {sender_id}  "
                  f"proto={my_proto_to_sender}  hops={new_hops}  "
                  f"cost={best_indirect_cost:.4f}")


def prune_stale_routes():
    """Remove link_stats and routing_table entries that have timed out."""
    now = time.time()
    stale_links  = [k for k, v in link_stats.items()
                    if now - v["last_seen"] > ROUTE_TIMEOUT]
    stale_routes = [k for k, v in routing_table.items()
                    if now - v["last_seen"] > ROUTE_TIMEOUT]
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
            r      = routing_table[dest]
            proto  = r["best_protocol"]
            w_cost = r.get("wifi_cost")
            b_cost = r.get("ble_cost")
            w_lat  = r.get("wifi_lat")
            b_lat  = r.get("ble_lat")

            w_tag      = " <BEST" if proto == "WiFi" else ""
            b_tag      = " <BEST" if proto == "BLE"  else ""
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
    """
    Send a neighbour-discovery Hello over both WiFi (UDP broadcast) and
    BLE (advertisement).  Also proxy-advertises WiFi-only neighbours
    over BLE when this node is dual-protocol.
    """
    ts   = time.time()
    rssi = wifi_code.wifi_rssi()

    # Compact routing snapshot to share with neighbours
    rt_share = {}
    for dest, r in routing_table.items():
        rt_share[dest] = {
            "next_hop"      : r["next_hop"],
            "best_protocol" : r["best_protocol"],
            "hop_count"     : r["hop_count"],
            "avg_latency_ms": r["avg_latency_ms"],
            "packet_loss"   : r["packet_loss"],
            "cost"          : r["cost"],
        }

    # ── WiFi Hello ─────────────────────────────────────────────────
    hello = {
        "type"     : "HELLO",
        "node_id"  : NODE_ID,
        "protocol" : "WiFi",
        "timestamp": ts,
        "ip"       : wifi_code.my_ip,
        "rssi"     : rssi,
        "routing"  : rt_share,
    }
    sign_packet(hello)
    wifi_code.udp_broadcast(UDP_MESH_PORT, hello)

    # ── BLE Hello beacon ───────────────────────────────────────────
    ble_samples = [s for (_, p), lnk in link_stats.items()
                   for s in lnk["latency_samples"] if p == "BLE"]
    avg_ble_lat = sum(ble_samples) / len(ble_samples) if ble_samples else 0.0
    ble_code.ble_advertise(BLE_PKT_TYPE_HELLO, 0, ts, rssi, avg_ble_lat, 0.0)

    neighbours = list(set(n for (n, _) in link_stats.keys()))
    print(f"[Hello] WiFi+BLE broadcast  |  known neighbours: {neighbours}")

    # ── Proxy-advertise WiFi-only neighbours over BLE ───────────────
    if wifi_code.wifi_active and ble_code.ble_active:
        now_proxy = time.time()
        proxied   = []
        for (node_id, proto), lnk in list(link_stats.items()):
            if proto != "WiFi":
                continue
            if now_proxy - lnk["last_seen"] > ROUTE_TIMEOUT:
                continue
            ble_lnk = link_stats.get((node_id, "BLE"))
            has_ble = ble_lnk and (now_proxy - ble_lnk["last_seen"] < ROUTE_TIMEOUT)
            if has_ble:
                continue   # already has BLE – no need to proxy
            lat        = avg_latency(node_id, "WiFi")
            loss       = lnk["packet_loss"]
            rssi_proxy = lnk["rssi"]
            # Use seq_hop=1 to signal this is a 1-hop relay
            # (not a direct link from the proxied node)
            ble_code.ble_advertise_proxy(
                node_id, BLE_PKT_TYPE_HELLO, 1,
                now_proxy, rssi_proxy, lat, loss)
            proxied.append(node_id)
        if proxied:
            print(f"[Hello] BLE-proxied WiFi-only nodes: {proxied}")


# ══════════════════════════════════════════════
#  PING NEIGHBOURS  (measure RTT per protocol)
# ══════════════════════════════════════════════

def ping_all_neighbours():
    """
    Send WiFi PING to every known WiFi neighbour and emit a BLE PING beacon.

    WiFi PINGs measure round-trip time.
    BLE PING beacons prompt neighbours to PONG via WiFi, giving us a
    real BLE link quality measurement.
    """
    now = time.time()

    for (node_id, proto), lnk in list(link_stats.items()):
        if proto != "WiFi":
            continue
        if not lnk.get("ip"):
            continue
        if now - lnk["last_seen"] > ROUTE_TIMEOUT:
            continue

        ping_pkt = {
            "type"     : "PING",
            "node_id"  : NODE_ID,
            "protocol" : "WiFi",
            "timestamp": now,
            "ticks_ms" : time.ticks_ms(),   # ms precision for RTT
        }
        sign_packet(ping_pkt)
        ok = wifi_code.udp_send(lnk["ip"], UDP_MESH_PORT, ping_pkt)
        if ok:
            get_link(node_id, "WiFi")["sent_count"] += 1
            ping_pending[(node_id, "WiFi")] = time.ticks_ms()

    # BLE PING beacon – neighbours respond with WiFi PONG + their BLE RSSI
    ble_code.ble_advertise(BLE_PKT_TYPE_PING, 0, now, wifi_code.wifi_rssi(), 0.0, 0.0)


# ══════════════════════════════════════════════
#  METRIC PACKETS  (WiFi + BLE simultaneously)
# ══════════════════════════════════════════════

def send_metrics():
    """
    Increment sequence number, aggregate per-protocol stats, and emit:
      1. A WiFi UDP metric packet to the gateway.
      2. A compact BLE advertisement for the gateway's BLE scanner.
    Then prints the current routing table.
    """
    global seq_number
    seq_number += 1
    ts   = time.time()
    rssi = wifi_code.wifi_rssi()

    # Aggregate per-protocol metrics across all links
    w_lats   = [s for (_, p), lnk in link_stats.items() for s in lnk["latency_samples"] if p == "WiFi"]
    b_lats   = [s for (_, p), lnk in link_stats.items() for s in lnk["latency_samples"] if p == "BLE"]
    w_losses = [lnk["packet_loss"] for (_, p), lnk in link_stats.items() if p == "WiFi"]
    b_losses = [lnk["packet_loss"] for (_, p), lnk in link_stats.items() if p == "BLE"]
    b_rssies = [lnk["rssi"]        for (_, p), lnk in link_stats.items() if p == "BLE"]
    w_powers = [lnk["power_cost"]  for (_, p), lnk in link_stats.items() if p == "WiFi"]
    b_powers = [lnk["power_cost"]  for (_, p), lnk in link_stats.items() if p == "BLE"]

    avg_w_lat = sum(w_lats) / len(w_lats) if w_lats else 0.0
    if avg_w_lat == 0.0 and wifi_code.wifi_active:
        wifi_rssi_val = wifi_code.wifi_rssi()
        if wifi_rssi_val > -99:
            avg_w_lat = max(5.0, min(200.0, (-wifi_rssi_val - 30) * 1.5))

    avg_b_lat   = sum(b_lats)   / len(b_lats)   if b_lats   else 0.0
    if avg_b_lat == 0.0:
        ble_rssi_samples = [lnk["rssi"] for (_, p), lnk in link_stats.items()
                            if p == "BLE" and lnk["rssi"] > -99]
        if ble_rssi_samples:
            avg_ble_rssi_est = sum(ble_rssi_samples) / len(ble_rssi_samples)
            avg_b_lat = max(20.0, min(120.0, (avg_ble_rssi_est + 40) * -1.375 + 25))
    avg_w_loss  = sum(w_losses) / len(w_losses) if w_losses else 0.0
    avg_b_loss  = sum(b_losses) / len(b_losses) if b_losses else 0.0
    avg_b_rssi  = sum(b_rssies) / len(b_rssies) if b_rssies else -99
    avg_w_power = sum(w_powers) / len(w_powers) if w_powers else 0.5
    avg_b_power = sum(b_powers) / len(b_powers) if b_powers else 0.5

    # Full routing snapshot for the gateway
    rt_snapshot = {}
    now_rt = time.time()
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

    for (node_id, proto), lnk in link_stats.items():
        if node_id in rt_snapshot:
            continue
        if now_rt - lnk["last_seen"] > ROUTE_TIMEOUT:
            continue
        lat_est = avg_latency(node_id, proto)
        if lat_est >= 9999.0:
            rssi_v = lnk["rssi"]
            if proto == "BLE" and rssi_v > -99:
                lat_est = max(20.0, min(120.0, (rssi_v + 40) * -1.375 + 25))
            elif proto == "WiFi" and rssi_v > -99:
                lat_est = max(5.0, min(200.0, (-rssi_v - 30) * 1.5))
            else:
                lat_est = 88.0 if proto == "BLE" else 50.0
        cost_est = compute_cost(lat_est, lnk["packet_loss"], lnk["power_cost"])
        rt_snapshot[node_id] = {
            "next_hop"      : node_id,
            "best_protocol" : proto,
            "hop_count"     : 1,
            "avg_latency_ms": round(lat_est, 2),
            "packet_loss"   : lnk["packet_loss"],
            "cost"          : round(cost_est, 6),
            "wifi_cost"     : round(cost_est, 6) if proto == "WiFi" else None,
            "ble_cost"      : round(cost_est, 6) if proto == "BLE"  else None,
            "wifi_lat"      : round(lat_est, 2)  if proto == "WiFi" else None,
            "ble_lat"       : round(lat_est, 2)  if proto == "BLE"  else None,
        }

    # ── 1. WiFi metric packet → gateway ────────────────────────────
    wifi_pkt = {
        "type"         : "METRIC",
        "node_id"      : NODE_ID,
        "protocol"     : "WiFi",
        "timestamp"    : ts,
        "seq_number"   : seq_number,
        "hop_count"    : 0,
        "rssi"         : rssi,
        "ip"           : wifi_code.my_ip,
        "neighbours"   : list(set(
            n for (n, p), lnk in link_stats.items()
            if (time.time() - lnk["last_seen"]) < ROUTE_TIMEOUT
        )),
        "routing_table": rt_snapshot,
        "route_mode"   : route_mode,
        "weights"      : {
            "w_latency"     : W_LATENCY,
            "w_packet_loss" : W_PACKET_LOSS,
            "w_power"       : W_POWER,
        },
        "metrics": {
            "wifi_avg_latency_ms": round(avg_w_lat,   2),
            "ble_avg_latency_ms" : round(avg_b_lat,   2),
            "wifi_packet_loss"   : round(avg_w_loss,  4),
            "ble_packet_loss"    : round(avg_b_loss,  4),
            "wifi_rssi"          : rssi,
            "ble_rssi"           : round(avg_b_rssi,  1),
            "wifi_power_cost"    : round(avg_w_power, 4),
            "ble_power_cost"     : round(avg_b_power, 4),
        },
    }
    sign_packet(wifi_pkt)
    ok = wifi_code.udp_send(GATEWAY_IP, UDP_GW_PORT, wifi_pkt)
    if ok:
        get_link("GATEWAY", "WiFi")["sent_count"] += 1

    # ── 2. BLE metric advertisement ────────────────────────────────
    ble_code.ble_advertise(BLE_PKT_TYPE_METRIC, seq_number & 0xFF,
                           ts, rssi, avg_b_lat, avg_b_loss)

    active = ("WiFi+" if wifi_code.wifi_active else "") + ("BLE" if ble_code.ble_active else "")
    print(f"[Metric] [{active}] seq={seq_number} wifi_rssi={rssi}dBm  |  "
          f"ble_lat={avg_b_lat:.1f}ms")

    # ── 3. Print routing decision ───────────────────────────────────
    print_routing_table()


# ══════════════════════════════════════════════
#  PROCESS INCOMING WiFi PACKETS
# ══════════════════════════════════════════════

def process_wifi_packets():
    """
    Drain the UDP receive queue (non-blocking) and dispatch by packet type:

      HELLO      – record link, learn indirect routes, rebuild routing table
      PING       – reply with PONG + BLE RSSI we measured for that sender
      PONG       – record RTT, update BLE RSSI, rebuild routing table
      METRIC     – relay towards gateway (mesh forwarding, max 10 hops)
      ROUTE_PREF – update cost-function weights from dashboard; ACK back
    """
    global W_LATENCY, W_PACKET_LOSS, W_POWER, route_mode

    try:
        while True:
            data, addr = wifi_code.udp_sock.recvfrom(2048)
            sender_ip  = addr[0]
            recv_ts    = time.time()

            try:
                pkt = json.loads(data.decode())
            except Exception:
                continue

            if not verify_packet(pkt):
                print(f"[UDP]  Dropped packet with invalid signature from {sender_ip}")
                continue

            ptype   = pkt.get("type")
            node_id = pkt.get("node_id", "")
            if node_id == NODE_ID or not ble_code.valid_node_id(node_id):
                continue   # ignore our own reflections and rogue nodes

            # ── HELLO ──────────────────────────────────────────────
            if ptype == "HELLO":
                lat_ms = max(0.0, (recv_ts - pkt.get("timestamp", recv_ts)) * 1000)
                record_latency(node_id, "WiFi", lat_ms, pkt.get("rssi", -99))
                get_link(node_id, "WiFi")["ip"] = pkt.get("ip", sender_ip)
                my_cost = routing_table.get(node_id, {}).get("cost", 50.0)
                learn_indirect_routes(node_id, pkt.get("routing", {}), my_cost)
                rebuild_routing_table()

            # ── PING ───────────────────────────────────────────────
            elif ptype == "PING":
                pong = {
                    "type"              : "PONG",
                    "node_id"           : NODE_ID,
                    "protocol"          : "WiFi",
                    "ping_ts"           : pkt.get("timestamp"),
                    "ping_ticks_ms"     : pkt.get("ticks_ms"),   # echo for accurate RTT
                    "timestamp"         : recv_ts,
                    "ble_rssi_of_sender": get_link(node_id, "BLE")["rssi"],
                }
                sign_packet(pong)
                wifi_code.udp_send(sender_ip, UDP_MESH_PORT, pong)

            # ── PONG ───────────────────────────────────────────────
            elif ptype == "PONG":
                ping_ticks = pkt.get("ping_ticks_ms")
                if ping_ticks is not None:
                    rtt_ms = time.ticks_diff(time.ticks_ms(), ping_ticks)
                else:
                    ping_ts = pkt.get("ping_ts", 0)
                    rtt_ms  = (recv_ts - ping_ts) * 1000 if ping_ts else 0
                rtt_ms = float(rtt_ms)

                # Cap at 400 ms – stale PONGs are silently dropped
                if rtt_ms < 0 or rtt_ms > 400:
                    ping_pending.pop((node_id, "WiFi"), None)
                    continue

                record_latency(node_id, "WiFi", rtt_ms, pkt.get("rssi", wifi_code.wifi_rssi()))

                # Also record BLE RSSI reported by the peer
                ble_rssi = pkt.get("ble_rssi_of_sender", -99)
                if ble_rssi > -99:
                    lnk = get_link(node_id, "BLE")
                    lnk["rssi"]       = ble_rssi
                    lnk["last_seen"]  = recv_ts
                    lnk["power_cost"] = min(1.0, max(0.05, (-ble_rssi - 50) / 40.0))

                ping_pending.pop((node_id, "WiFi"), None)
                rebuild_routing_table()
                print(f"[PONG] {node_id} WiFi RTT={rtt_ms:.1f}ms  BLE_RSSI={ble_rssi}dBm")

            # ── METRIC (relay) ─────────────────────────────────────
            elif ptype == "METRIC":
                hop = pkt.get("hop_count", 0) + 1
                if hop <= 10:
                    pkt["hop_count"]  = hop
                    pkt["relayed_by"] = NODE_ID
                    sign_packet(pkt)
                    wifi_code.udp_send(GATEWAY_IP, UDP_GW_PORT, pkt)
                    print(f"[Relay] Forwarded METRIC from {node_id} hop={hop}")

            # ── ROUTE_PREF (dashboard weight update) ───────────────
            elif ptype == "ROUTE_PREF":
                target = pkt.get("target", "")
                if target == NODE_ID:
                    new_wl   = pkt.get("w_latency")
                    new_wp   = pkt.get("w_packet_loss")
                    new_ww   = pkt.get("w_power")
                    new_mode = pkt.get("mode", "balanced")
                    if new_wl is not None and new_wp is not None and new_ww is not None:
                        W_LATENCY     = float(new_wl)
                        W_PACKET_LOSS = float(new_wp)
                        W_POWER       = float(new_ww)
                        route_mode    = new_mode
                        rebuild_routing_table()
                        print(f"[RoutePref] Updated to {new_mode}: "
                              f"L={W_LATENCY} P={W_PACKET_LOSS} W={W_POWER}")
                        # ACK back so the dashboard knows the update was applied
                        ack = {
                            "type"          : "ROUTE_PREF_ACK",
                            "node_id"       : NODE_ID,
                            "mode"          : new_mode,
                            "w_latency"     : W_LATENCY,
                            "w_packet_loss" : W_PACKET_LOSS,
                            "w_power"       : W_POWER,
                            "timestamp"     : time.time(),
                        }
                        sign_packet(ack)
                        wifi_code.udp_send(sender_ip, UDP_MESH_PORT, ack)

    except OSError as e:
        # errno 11 = EAGAIN: non-blocking socket has no data – completely normal.
        # Any other OSError is a real socket fault and should be logged.
        import errno as _errno
        if hasattr(e, 'args') and e.args and e.args[0] != _errno.EAGAIN:
            print(f"[UDP]  recv error (errno {e.args[0]}): {e}")


# ══════════════════════════════════════════════
#  PROCESS BLE RECEIVE BUFFER
# ══════════════════════════════════════════════

def process_ble_buffer():
    """
    Drain ble_code.ble_rx_buffer (filled by the hardware IRQ) and
    update link_stats + routing table.

    Packet types handled:
      HELLO / METRIC – record BLE link quality; relay to gateway via WiFi
                       if sender has no WiFi link (BLE→WiFi relay)
      PING           – respond via WiFi PONG carrying the BLE RSSI we measured
    """
    while ble_code.ble_rx_buffer:
        decoded  = ble_code.ble_rx_buffer.pop(0)
        node_id  = decoded.get("node_id", "")
        pkt_type = decoded.get("pkt_type")
        adv_rssi = decoded.get("adv_rssi", -99)
        lat_ms   = decoded.get("lat_ms", 0.0)
        loss     = decoded.get("loss", 0.0)
        seq_hop  = decoded.get("seq_hop", 0)
        now      = time.time()

        # Proxied HELLO (seq_hop=1) = WiFi-only node advertised by
        # a dual-protocol relay. NOT a direct BLE link — skip
        # direct link recording to avoid false routes.
        if pkt_type == BLE_PKT_TYPE_HELLO and seq_hop == 1:
            print(f"[BLE]  Proxied Hello from {node_id} "
                  f"(relayed, not direct)  RSSI={adv_rssi}dBm")
            rebuild_routing_table()
            # Skip to next packet — do not record as direct BLE link
            continue

        lnk = get_link(node_id, "BLE")
        lnk["rssi"]       = adv_rssi
        lnk["last_seen"]  = now
        lnk["power_cost"] = min(1.0, max(0.05, (-adv_rssi - 50) / 40.0))

        if pkt_type in (BLE_PKT_TYPE_HELLO, BLE_PKT_TYPE_METRIC):
            if lat_ms > 0:
                lnk["latency_samples"].append(lat_ms)
                if len(lnk["latency_samples"]) > 10:
                    lnk["latency_samples"].pop(0)

            if pkt_type == BLE_PKT_TYPE_METRIC:
                lnk["recv_count"] += 1
                lnk["packet_loss"] = loss

                # ── BLE→WiFi relay ─────────────────────────────────────────
                # If we have WiFi but the sender only has BLE (no WiFi link
                # seen for them), forward their metric to the gateway on their
                # behalf so they appear in the Health Matrix.
                wifi_key       = (node_id, "WiFi")
                sender_has_wifi = (wifi_key in link_stats
                                   and link_stats[wifi_key]["last_seen"] > 0
                                   and (time.time() - link_stats[wifi_key]["last_seen"]) < ROUTE_TIMEOUT)
                if wifi_code.wifi_active and not sender_has_wifi:
                    # Estimate latency if not available
                    relay_lat = lat_ms
                    if relay_lat == 0.0 and adv_rssi > -99:
                        relay_lat = max(20.0, min(120.0, (adv_rssi + 40) * -1.375 + 25))

                    # Build what we know about the relayed node's peers
                    # We are a known neighbour of the relayed node since we can hear it
                    relay_neighbours = [NODE_ID]
                    relay_rt = {
                        NODE_ID: {
                            "next_hop"      : NODE_ID,
                            "best_protocol" : "BLE",
                            "hop_count"     : 1,
                            "avg_latency_ms": round(relay_lat, 2),
                            "packet_loss"   : loss,
                            "cost"          : round(compute_cost(relay_lat, loss,
                                                min(1.0, max(0.05, (-adv_rssi - 50) / 40.0))), 6),
                            "wifi_cost"     : None,
                            "ble_cost"      : round(compute_cost(relay_lat, loss,
                                                min(1.0, max(0.05, (-adv_rssi - 50) / 40.0))), 6),
                            "wifi_lat"      : None,
                            "ble_lat"       : round(relay_lat, 2),
                        }
                    }

                    # Also include any other peers we know the relayed node has
                    # (if they appear in our own link_stats as BLE neighbours)
                    for (peer_id, peer_proto), peer_lnk in link_stats.items():
                        if peer_id == node_id or peer_id == NODE_ID:
                            continue
                        if now - peer_lnk["last_seen"] > ROUTE_TIMEOUT:
                            continue
                        # Only include BLE peers for BLE-only relayed nodes
                        # A BLE-only node cannot directly reach WiFi-only nodes
                        if peer_proto != "BLE":
                            continue
                        peer_lat = avg_latency(peer_id, peer_proto)
                        if peer_lat >= 9999.0 and peer_lnk["rssi"] > -99:
                            peer_rssi = peer_lnk["rssi"]
                            peer_lat = (max(20.0, min(120.0, (peer_rssi + 40) * -1.375 + 25))
                                        if peer_proto == "BLE"
                                        else max(5.0, min(200.0, (-peer_rssi - 30) * 1.5)))
                        relay_neighbours.append(peer_id)
                        relay_rt[peer_id] = {
                            "next_hop"      : peer_id,
                            "best_protocol" : peer_proto,
                            "hop_count"     : 1,
                            "avg_latency_ms": round(peer_lat, 2),
                            "packet_loss"   : peer_lnk["packet_loss"],
                            "cost"          : round(compute_cost(peer_lat, peer_lnk["packet_loss"],
                                                                peer_lnk["power_cost"]), 6),
                            "wifi_cost"     : round(compute_cost(peer_lat, peer_lnk["packet_loss"],
                                                    peer_lnk["power_cost"]), 6) if peer_proto == "WiFi" else None,
                            "ble_cost"      : round(compute_cost(peer_lat, peer_lnk["packet_loss"],
                                                    peer_lnk["power_cost"]), 6) if peer_proto == "BLE"  else None,
                            "wifi_lat"      : round(peer_lat, 2) if peer_proto == "WiFi" else None,
                            "ble_lat"       : round(peer_lat, 2) if peer_proto == "BLE"  else None,
                        }

                    relay_pkt = {
                        "type"         : "METRIC",
                        "node_id"      : node_id,
                        "protocol"     : "BLE",
                        "timestamp"    : now,
                        "seq_number"   : decoded.get("seq_hop", 0),
                        "hop_count"    : 1,
                        "rssi"         : adv_rssi,
                        "ip"           : "BLE-only",
                        "relayed_by"   : NODE_ID,
                        "neighbours"   : list(set(relay_neighbours)),
                        "routing_table": relay_rt,
                        "metrics": {
                            "wifi_avg_latency_ms": 0,
                            "ble_avg_latency_ms" : relay_lat,
                            "wifi_packet_loss"   : 1.0,
                            "ble_packet_loss"    : loss,
                            "wifi_rssi"          : -99,
                            "ble_rssi"           : adv_rssi,
                            "wifi_power_cost"    : 1.0,
                            "ble_power_cost"     : min(1.0, max(0.05, (-adv_rssi - 50) / 40.0)),
                        },
                    }
                    sign_packet(relay_pkt)
                    ok = wifi_code.udp_send(GATEWAY_IP, UDP_GW_PORT, relay_pkt)
                    if ok:
                        print(f"[Relay] BLE→WiFi: forwarded {node_id} metric to gateway")

            rebuild_routing_table()

            # Throttle: only print every BLE_PRINT_EVERY messages per node
            ble_code._ble_recv_count[node_id] = ble_code._ble_recv_count.get(node_id, 0) + 1
            if ble_code._ble_recv_count[node_id] % ble_code.BLE_PRINT_EVERY == 1:
                label = "Hello" if pkt_type == BLE_PKT_TYPE_HELLO else "Metric"
                print(f"[BLE]  {label} from {node_id}  RSSI={adv_rssi}dBm  "
                      f"(#{ble_code._ble_recv_count[node_id]})")

        elif pkt_type == BLE_PKT_TYPE_PING:
            # Sender pinged via BLE adv – respond via WiFi PONG with BLE RSSI included
            wifi_ip = get_link(node_id, "WiFi").get("ip")
            if wifi_ip:
                pong = {
                    "type"              : "PONG",
                    "node_id"           : NODE_ID,
                    "protocol"          : "BLE_via_WiFi",
                    "ping_ts"           : decoded.get("ts"),
                    "timestamp"         : now,
                    "ble_rssi_of_sender": adv_rssi,
                }
                sign_packet(pong)
                wifi_code.udp_send(wifi_ip, UDP_MESH_PORT, pong)


# ══════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════

def main():
    global last_hello_time, last_metric_time, last_ping_time
    global W_LATENCY, W_PACKET_LOSS, W_POWER, route_mode

    print("╔══════════════════════════════════════════╗")
    print(f"║  Mesh Node  {NODE_ID:<8}  (Pico W)      ║")
    print("║  Dual-Protocol: WiFi + BLE               ║")
    print("╚══════════════════════════════════════════╝")

    # ── Try WiFi (non-fatal if it fails) ──────────────────────────
    if ENABLE_WIFI:
        wifi_code.connect_wifi(WIFI_SSID, WIFI_PASSWORD)
        if wifi_code.wifi_active:
            wifi_code.setup_udp(UDP_MESH_PORT)
    else:
        print("[Node] WiFi Disabled")

    # ── Start BLE (non-fatal if it fails) ─────────────────────────
    if ENABLE_BLE:
        ble_code.setup_ble(NODE_ID)
    else:
        print("[Node] BLE Disabled")

    if not wifi_code.wifi_active and not ble_code.ble_active:
        print("[FATAL] Both WiFi and BLE unavailable. Cannot start.")
        return

    # ── Report active protocols ────────────────────────────────────
    active = []
    if wifi_code.wifi_active: active.append(f"WiFi ({wifi_code.my_ip})")
    if ble_code.ble_active:   active.append("BLE")
    print(f"\n[Node] {NODE_ID} ready  –  Active: {' + '.join(active)}\n")

    last_hello_time  = 0
    last_metric_time = 0
    last_ping_time   = 0
    last_wifi_retry  = 0
    last_wifi_check  = 0
    WIFI_RETRY_INTERVAL = 60   # trigger a new reconnect attempt every 60 s
    WIFI_CHECK_INTERVAL = 5    # check if background connect succeeded every 5 s

    while True:
        now = time.time()

        # ── WiFi background reconnect logic ───────────────────────
        if ENABLE_WIFI and not wifi_code.wifi_active:
            if now - last_wifi_check >= WIFI_CHECK_INTERVAL:
                if wifi_code.wlan and wifi_code.wlan.isconnected():
                    wifi_code.my_ip       = wifi_code.wlan.ifconfig()[0]
                    wifi_code.wifi_active = True
                    if wifi_code.udp_sock is None:
                        wifi_code.setup_udp(UDP_MESH_PORT)
                    print(f"[WiFi] Connected  IP={wifi_code.my_ip}")
                    broadcast_hello()   # announce immediately on reconnect
                last_wifi_check = now

            if now - last_wifi_retry >= WIFI_RETRY_INTERVAL:
                wifi_code.check_wifi_reconnect()
                last_wifi_retry = now

        # A. Neighbour Discovery
        if now - last_hello_time >= HELLO_INTERVAL:
            broadcast_hello()
            prune_stale_routes()
            last_hello_time = now

        # B. RTT Probes
        if now - last_ping_time >= PING_INTERVAL:
            ping_all_neighbours()
            last_ping_time = now

        # C. Metric Packets
        if now - last_metric_time >= METRIC_INTERVAL:
            send_metrics()
            last_metric_time = now

        # D. Receive and process incoming WiFi packets
        if wifi_code.wifi_active and wifi_code.udp_sock is not None:
            process_wifi_packets()

        # E. Process BLE scan results from IRQ buffer
        if ble_code.ble_active:
            process_ble_buffer()

        time.sleep(0.05)


# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════
if __name__ == "__main__":
    main()