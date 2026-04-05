"""
╔══════════════════════════════════════════════════════════════════╗
║       ATTACKER NODE  –  Security Demonstration Script            ║
║       Simulates a rogue device attempting packet injection        ║
╠══════════════════════════════════════════════════════════════════╣
║  PURPOSE: Demonstrate that unsigned / wrongly-signed packets     ║
║  are detected and dropped by legitimate mesh nodes and gateway.  ║
║                                                                  ║
║  ATTACKS DEMONSTRATED:                                           ║
║  1. Unsigned HELLO          – spoof a fake neighbour node        ║
║  2. Wrong-key HELLO         – sign with a guessed key            ║
║  3. Fake METRIC (no sig)    – inject rogue sensor data           ║
║  4. Fake METRIC (wrong key) – signed but with wrong secret       ║
║  5. ROUTE_PREF hijack       – override routing weights           ║
║  6. Node impersonation      – tamper payload after signing       ║
║  7. Replay attack           – resend a sniffed valid packet      ║
║  8. Fake ROUTE_PREF_ACK     – spoof a route-pref confirmation    ║
║  9. Indirect route poisoning – inject false routing table        ║
║  DEMO. Valid signed HELLO   – show correct key is accepted       ║
║                                                                  ║
║  HOW SIGNING WORKS IN THE CURRENT CODEBASE:                      ║
║                                                                  ║
║  Nodes (MicroPython) use _sorted_json() — a custom serialiser    ║
║  that sorts dict keys and strips spaces — then HMAC-SHA256.      ║
║                                                                  ║
║  Gateway uses json.dumps(sort_keys=True, separators=(',',':'))   ║
║  which produces IDENTICAL output for well-formed packets.        ║
║                                                                  ║
║  This script uses the gateway method (standard library hmac)     ║
║  because we run on CPython, not MicroPython.                     ║
║                                                                  ║
║  Run this on any machine on the same WiFi as the mesh.           ║
║  Python 3.8+ required  (standard library only).                  ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python attacker_node.py [options]

    --target-ip     IP of a live mesh node  (default: 10.202.64.43)
    --gateway-ip    IP of the gateway RPi   (default: 10.202.64.140)
    --target-node   Node ID to attack       (default: NODE_lx)
    --skip-sniff    Skip packet sniffing phase
    --delay         Seconds between attacks (default: 1.5)
"""

import socket
import json
import time
import hashlib
import hmac as _hmac_mod
import argparse

# ══════════════════════════════════════════════
#  CONFIG — mirrors node_main.py network settings
# ══════════════════════════════════════════════

DEFAULT_NODE_IP    = "10.202.64.62"    # A live mesh node to attack directly
DEFAULT_GATEWAY_IP = "10.202.64.140"   # Raspberry Pi gateway (matches node_main.py)
UDP_MESH_PORT      = 5005              # Node-to-node mesh port
UDP_GW_PORT        = 5006              # Node-to-gateway data port

CORRECT_KEY = b"mesh_secret_2106"     # The real shared key — attacker does NOT know this
WRONG_KEY   = b"i_am_a_hacker_lol"   # Attacker's guessed key

ATTACKER_ID  = "NODE_EV"   # Fake node ID used in injected packets (valid format)
ATTACKER_IP  = "10.202.64.99"


# ══════════════════════════════════════════════
#  HMAC / SIGNING HELPERS
#
#  The gateway's verify_packet_raw() signs with:
#    json.dumps(pkt, sort_keys=True, separators=(',', ':'))
#
#  node_main.py's _sorted_json() produces identical output for
#  well-formed dicts, so we use the same gateway-style method here
#  (standard library json — no MicroPython needed on attacker machine).
# ══════════════════════════════════════════════

def _sign_gateway_style(pkt: dict, key: bytes) -> dict:
    """
    Sign a packet the same way gateway.py does.
    Matches verify_packet_raw() in gateway.py exactly.
    Also matches node_main.py's verify_packet() for well-formed dicts.
    """
    pkt.pop("sig", None)
    payload = json.dumps(pkt, sort_keys=True, separators=(',', ':')).encode()
    sig = _hmac_mod.new(key, payload, hashlib.sha256).hexdigest()
    pkt["sig"] = sig
    return pkt


def sign_correct(pkt: dict) -> dict:
    """Sign with the real key — packet will be ACCEPTED."""
    return _sign_gateway_style(pkt, CORRECT_KEY)


def sign_wrong(pkt: dict) -> dict:
    """Sign with the attacker's guessed key — packet will be DROPPED."""
    return _sign_gateway_style(pkt, WRONG_KEY)


# ══════════════════════════════════════════════
#  TRANSPORT HELPERS
# ══════════════════════════════════════════════

def udp_send(ip: str, port: int, obj: dict, label: str = "") -> None:
    """Send a UDP packet and print a one-line status."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = json.dumps(obj).encode()
        sock.sendto(data, (ip, port))
        sig = obj.get("sig")
        sig_preview = sig[:16] + "..." if sig else "MISSING"
        print(f"  ↑ Sent → {ip}:{port}  [{label}]  sig={sig_preview}")
    except Exception as e:
        print(f"  ✗ Send failed: {e}")
    finally:
        sock.close()


def udp_broadcast(port: int, obj: dict, label: str = "") -> None:
    """Broadcast a UDP packet to 255.255.255.255 (mirrors wifi_code.udp_broadcast)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        data = json.dumps(obj).encode()
        sock.sendto(data, ("255.255.255.255", port))
        sig = obj.get("sig")
        sig_preview = sig[:16] + "..." if sig else "MISSING"
        print(f"  ↑ Broadcast → 255.255.255.255:{port}  [{label}]  sig={sig_preview}")
    except Exception as e:
        print(f"  ✗ Broadcast failed: {e}")
    finally:
        sock.close()


# ══════════════════════════════════════════════
#  PACKET SNIFFING — for replay attack
# ══════════════════════════════════════════════

def sniff_one_packet(port: int = UDP_MESH_PORT, timeout: float = 10.0) -> dict | None:
    """
    Listen on the mesh port and capture the first valid JSON packet.
    Used to demonstrate a replay attack.
    The mesh port receives HELLO, PING, PONG, and ROUTE_PREF_ACK packets.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(timeout)
    print(f"\n  [Sniff] Listening on :{port} for up to {timeout}s ...")
    try:
        data, addr = sock.recvfrom(4096)
        pkt = json.loads(data.decode())
        print(f"  [Sniff] Captured from {addr[0]}  "
              f"type={pkt.get('type')}  "
              f"node={pkt.get('node_id')}  "
              f"sig={str(pkt.get('sig', ''))[:16]}...")
        return pkt
    except socket.timeout:
        print("  [Sniff] Timed out – no packet captured. Replay attack skipped.")
        return None
    except Exception as e:
        print(f"  [Sniff] Error: {e}")
        return None
    finally:
        sock.close()


# ══════════════════════════════════════════════
#  ATTACK 1 — Unsigned HELLO injection
#
#  Targets: All nodes via UDP broadcast (mirrors wifi_code.udp_broadcast)
#           and direct unicast to target node.
#
#  node_main.py defence: verify_packet() checks for 'sig' field first.
#  Gateway defence: verify_packet_raw() returns False if sig missing.
#
#  Expected output on node: [HMAC] Missing sig! pkt keys=[...]
#  Expected output on gateway: packet silently dropped before processing
# ══════════════════════════════════════════════

def attack_unsigned_hello(target_ip: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 1: Unsigned HELLO injection")
    print("  Goal   : Fake a neighbour HELLO with no signature at all")
    print("  Targets: Broadcast + unicast to target node")
    print("  Expect : '[HMAC] Missing sig! pkt keys=[...]' → dropped")
    print("─" * 62)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : ATTACKER_IP,
        "rssi"     : -40,
        "routing"  : {},
        # ← no "sig" field intentionally
    }

    # Broadcast (same as how real nodes send HELLO)
    udp_broadcast(UDP_MESH_PORT, pkt, "UNSIGNED HELLO (broadcast)")
    # Also unicast directly at the target
    udp_send(target_ip, UDP_MESH_PORT, pkt, "UNSIGNED HELLO (unicast)")
    print("  Defence: verify_packet() → sig=None → '[HMAC] Missing sig!'")


# ══════════════════════════════════════════════
#  ATTACK 2 — Wrong-key HELLO injection
#
#  Attacker guesses the shared key and signs with it.
#  node_main.py: _hmac_sha256(SHARED_KEY, payload) → expected hex
#                sig != expected → dropped
#  Gateway: hmac.new(SHARED_KEY, ...) → same mismatch
#
#  Expected output on node: [HMAC] FAIL sig=<first16> exp=<first16>
# ══════════════════════════════════════════════

def attack_wrongkey_hello(target_ip: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 2: Wrong-key signed HELLO")
    print(f"  Goal   : Sign with guessed key '{WRONG_KEY.decode()}'")
    print("  Targets: Broadcast + unicast")
    print("  Expect : '[HMAC] FAIL sig=... exp=...' → dropped")
    print("─" * 62)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : ATTACKER_IP,
        "rssi"     : -40,
        "routing"  : {},
    }
    sign_wrong(pkt)

    udp_broadcast(UDP_MESH_PORT, pkt, "WRONG-KEY HELLO (broadcast)")
    udp_send(target_ip, UDP_MESH_PORT, pkt, "WRONG-KEY HELLO (unicast)")
    print("  Defence: HMAC recomputed with real key → mismatch → dropped")


# ══════════════════════════════════════════════
#  ATTACK 3 — Fake METRIC to gateway (no signature)
#
#  Targets port 5006 (UDP_GW_PORT) — the gateway metric listener.
#  Gateway defence: verify_packet_raw() checks sig before any processing.
#
#  Packet mirrors the full structure sent by send_metrics() in node_main.py,
#  including the nested "metrics" dict and "routing_table" snapshot.
#
#  Expected gateway output: verify_packet_raw returns False → dropped silently
# ══════════════════════════════════════════════

def attack_fake_metric_nosig(gateway_ip: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 3: Fake METRIC packet to gateway (no signature)")
    print("  Goal   : Inject a rogue node with impossibly good metrics")
    print("  Targets: Gateway port 5006 (UDP_GW_PORT)")
    print("  Expect : verify_packet_raw() → False → dropped silently")
    print("─" * 62)

    pkt = {
        "type"         : "METRIC",
        "node_id"      : "NODE_XX",       # non-existent attacker node
        "protocol"     : "WiFi",
        "timestamp"    : time.time(),
        "seq_number"   : 1,
        "hop_count"    : 0,
        "rssi"         : -20,             # suspiciously perfect signal
        "ip"           : ATTACKER_IP,
        "neighbours"   : ["NODE_lx", "NODE_02"],
        "routing_table": {
            "NODE_lx": {
                "next_hop"      : "NODE_lx",
                "best_protocol" : "WiFi",
                "hop_count"     : 1,
                "avg_latency_ms": 1.0,
                "packet_loss"   : 0.0,
                "cost"          : 0.001,
                "wifi_cost"     : 0.001,
                "ble_cost"      : None,
                "wifi_lat"      : 1.0,
                "ble_lat"       : None,
            }
        },
        "route_mode"   : "balanced",
        "weights"      : {"w_latency": 0.5, "w_packet_loss": 0.3, "w_power": 0.2},
        "metrics": {
            "wifi_avg_latency_ms": 1.0,   # impossibly low
            "ble_avg_latency_ms" : 1.0,
            "wifi_packet_loss"   : 0.0,
            "ble_packet_loss"    : 0.0,
            "wifi_rssi"          : -20,
            "ble_rssi"           : -20,
            "wifi_power_cost"    : 0.01,
            "ble_power_cost"     : 0.01,
        },
        # ← no "sig" field
    }

    udp_send(gateway_ip, UDP_GW_PORT, pkt, "FAKE METRIC (no sig)")
    print("  Defence: verify_packet_raw() → sig absent → False → dropped")


# ══════════════════════════════════════════════
#  ATTACK 4 — Fake METRIC to gateway (wrong key)
#
#  Same as Attack 3 but the attacker tries to sign it.
#  The gateway's HMAC recomputation with the real key will not match.
# ══════════════════════════════════════════════

def attack_fake_metric_wrongkey(gateway_ip: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 4: Fake METRIC packet to gateway (wrong key)")
    print("  Goal   : Sign with guessed key so gateway accepts it")
    print("  Targets: Gateway port 5006 (UDP_GW_PORT)")
    print("  Expect : HMAC mismatch → verify_packet_raw() → False → dropped")
    print("─" * 62)

    pkt = {
        "type"         : "METRIC",
        "node_id"      : "NODE_XX",
        "protocol"     : "WiFi",
        "timestamp"    : time.time(),
        "seq_number"   : 2,
        "hop_count"    : 0,
        "rssi"         : -20,
        "ip"           : ATTACKER_IP,
        "neighbours"   : ["NODE_lx"],
        "routing_table": {},
        "route_mode"   : "balanced",
        "weights"      : {"w_latency": 0.5, "w_packet_loss": 0.3, "w_power": 0.2},
        "metrics": {
            "wifi_avg_latency_ms": 1.0,
            "ble_avg_latency_ms" : 1.0,
            "wifi_packet_loss"   : 0.0,
            "ble_packet_loss"    : 0.0,
            "wifi_rssi"          : -20,
            "ble_rssi"           : -20,
            "wifi_power_cost"    : 0.01,
            "ble_power_cost"     : 0.01,
        },
    }
    sign_wrong(pkt)

    udp_send(gateway_ip, UDP_GW_PORT, pkt, "FAKE METRIC (wrong key)")
    print("  Defence: verify_packet_raw() recomputes HMAC with real key → mismatch")


# ══════════════════════════════════════════════
#  ATTACK 5 — ROUTE_PREF weight hijack
#
#  Targets the ROUTE_PREF handler in node_main.py:process_wifi_packets().
#  In the current code, ROUTE_PREF is handled BEFORE the node_id filter
#  because it uses "GATEWAY" as node_id.
#
#  The attacker tries to override W_LATENCY / W_PACKET_LOSS / W_POWER
#  on NODE_lx to force all traffic to BLE and eventually through the
#  attacker acting as a fake "relay".
#
#  node_main.py defence: verify_packet() is called at top of
#  process_wifi_packets() for ALL packets including ROUTE_PREF.
#
#  Also targets gateway port 5005 (mesh port) since gateway.py's
#  udp_mesh_listener also handles ROUTE_PREF_ACK on that port,
#  and the /route_pref REST endpoint requires gateway auth.
#
#  Expected: HMAC FAIL → W_LATENCY/W_PACKET_LOSS/W_POWER unchanged
# ══════════════════════════════════════════════

def attack_route_hijack(target_ip: str, target_node_id: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 5: ROUTE_PREF weight hijack")
    print(f"  Goal   : Force {target_node_id} to route all traffic via BLE")
    print(f"           (attacker pretends to be 'GATEWAY')")
    print("  Targets: Node mesh port 5005")
    print("  Expect : verify_packet() → HMAC FAIL → weights unchanged")
    print("─" * 62)

    pkt = {
        "type"         : "ROUTE_PREF",
        "node_id"      : "GATEWAY",       # must be "GATEWAY" to bypass node_id filter
        "target"       : target_node_id,  # the node we want to hijack
        "mode"         : "attacker_controlled",
        "w_latency"    : 0.0,             # ignore latency → force BLE
        "w_packet_loss": 0.0,             # ignore reliability
        "w_power"      : 1.0,             # maximise power weighting
        "timestamp"    : int(time.time()),
    }
    sign_wrong(pkt)   # signed with wrong key → will fail verify_packet()

    udp_send(target_ip, UDP_MESH_PORT, pkt, "ROUTE_PREF HIJACK (wrong key)")
    print("  Defence: verify_packet() called before ROUTE_PREF branch → dropped")
    print("  Note   : Even if node_id='GATEWAY' bypasses the ID filter,")
    print("           the HMAC check fires first in process_wifi_packets().")


# ══════════════════════════════════════════════
#  ATTACK 6 — Node impersonation via payload tampering
#
#  The attacker signs a packet with the wrong key, saves the sig,
#  then mutates the payload (swaps in a real node ID, improves RSSI).
#  The stored sig no longer matches the mutated payload.
#
#  This tests whether the HMAC covers all fields — it does, because
#  _sorted_json() / json.dumps(sort_keys=True) serialises the entire dict.
#
#  Expected: HMAC mismatch → impersonation blocked
# ══════════════════════════════════════════════

def attack_tampered_payload(target_ip: str, target_node_id: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 6: Payload tampering (impersonation)")
    print(f"  Goal   : Swap in real node ID '{target_node_id}' after signing")
    print("  Targets: Node mesh port 5005")
    print("  Expect : HMAC mismatch → impersonation blocked")
    print("─" * 62)

    # Step 1 — sign the attacker's real packet (with wrong key)
    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : ATTACKER_IP,
        "rssi"     : -60,
        "routing"  : {},
    }
    sign_wrong(pkt)   # sig covers ATTACKER_ID + rssi=-60

    # Step 2 — mutate payload AFTER signing
    pkt["node_id"] = target_node_id    # impersonate a real node
    pkt["rssi"]    = -20               # make ourselves look closer
    pkt["ip"]      = "10.202.64.50"    # fake a real-looking IP

    udp_send(target_ip, UDP_MESH_PORT, pkt, "TAMPERED PAYLOAD")
    print("  Defence: HMAC recomputed over mutated payload → mismatch → dropped")


# ══════════════════════════════════════════════
#  ATTACK 7 — Replay attack
#
#  The attacker captures a legitimately signed packet (from sniff phase)
#  and replays it verbatim. The signature is valid because it hasn't
#  been modified — HMAC alone cannot detect replays.
#
#  Current status: the codebase does NOT yet deduplicate on
#  (node_id, seq_number) pairs, so replayed packets MAY be accepted.
#
#  The gateway's seq_tracker only catches gaps in sequence numbers from
#  a given node — it doesn't explicitly reject exact duplicates within
#  a time window.
#
#  Expected: packet likely passes HMAC, may update health matrix
#  Recommendation: add (node_id, seq_number, protocol) dedup with 60s window
# ══════════════════════════════════════════════

def attack_replay(target_ip: str, sniffed: dict | None) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 7: Replay attack (resend a captured valid packet)")
    print("  Goal   : Re-inject a legitimately signed packet verbatim")
    print("  Targets: Node mesh port 5005")
    print("  Note   : HMAC alone cannot prevent replay attacks.")
    print("  Expect : ⚠  Packet may be ACCEPTED (known gap in defence)")
    print("─" * 62)

    if sniffed is None:
        print("  SKIPPED – no packet was sniffed (run near an active node,")
        print("  or remove --skip-sniff flag)")
        return

    pkt_type = sniffed.get("type", "?")
    node_id  = sniffed.get("node_id", "?")
    seq      = sniffed.get("seq_number", "?")
    print(f"  Replaying: type={pkt_type}  node={node_id}  seq={seq}")
    udp_send(target_ip, UDP_MESH_PORT, sniffed, "REPLAY (valid sig)")
    print("  ⚠  If node lacks (node_id, seq_number) dedup, this PASSES.")
    print("  Recommendation: track seen (node_id, seq_number) pairs in a")
    print("  60-second rolling window and drop exact duplicates.")


# ══════════════════════════════════════════════
#  ATTACK 8 — Fake ROUTE_PREF_ACK to gateway
#
#  The gateway's udp_mesh_listener() on port 5005 calls
#  process_route_pref_ack() when it sees type="ROUTE_PREF_ACK".
#  That function updates health_matrix[node_id]["route_mode"] and
#  health_matrix[node_id]["route_weights"].
#
#  If the attacker can forge a valid-looking ACK, they could make the
#  dashboard *think* a node accepted a routing mode it never received.
#
#  Variation A: no signature → dropped at verify_packet_raw()
#  Variation B: wrong-key signature → HMAC mismatch → dropped
# ══════════════════════════════════════════════

def attack_fake_route_pref_ack(gateway_ip: str, target_node_id: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 8: Fake ROUTE_PREF_ACK to gateway")
    print(f"  Goal   : Trick gateway into thinking {target_node_id} accepted")
    print("           a routing mode change it never received")
    print("  Targets: Gateway mesh port 5005 (udp_mesh_listener)")
    print("  Expect : verify_packet_raw() → HMAC fail → dropped")
    print("─" * 62)

    # Variation A — no signature
    pkt_nosig = {
        "type"         : "ROUTE_PREF_ACK",
        "node_id"      : target_node_id,
        "mode"         : "latency",       # attacker wants 'latency' mode logged
        "w_latency"    : 0.8,
        "w_packet_loss": 0.15,
        "w_power"      : 0.05,
        "timestamp"    : int(time.time()),
        # ← no sig
    }
    udp_send(gateway_ip, UDP_MESH_PORT, pkt_nosig, "FAKE ROUTE_PREF_ACK (no sig)")

    # Variation B — wrong key
    pkt_wrongkey = dict(pkt_nosig)
    pkt_wrongkey["timestamp"] = int(time.time())
    sign_wrong(pkt_wrongkey)
    udp_send(gateway_ip, UDP_MESH_PORT, pkt_wrongkey, "FAKE ROUTE_PREF_ACK (wrong key)")

    print("  Defence: verify_packet_raw() on port 5005 → dropped before")
    print("           process_route_pref_ack() is ever called.")


# ══════════════════════════════════════════════
#  ATTACK 9 — Indirect route poisoning via HELLO routing table
#
#  In node_main.py, process_wifi_packets() calls learn_indirect_routes()
#  when it receives a HELLO packet. The HELLO includes a "routing" dict
#  that the recipient uses to discover indirect routes.
#
#  If the attacker can inject a signed HELLO with a poisoned routing
#  table, it could redirect traffic for NODE_lx through the attacker.
#
#  This requires a valid signature, so the wrong-key version will be
#  dropped. This attack demonstrates what would happen if the key
#  were compromised — and why key secrecy is the root of trust.
#
#  The valid-key variation at the end of main() shows the "what-if".
# ══════════════════════════════════════════════

def attack_route_poisoning(target_ip: str, victim_node_id: str) -> None:
    print("\n" + "═" * 62)
    print("ATTACK 9: Indirect route poisoning via HELLO routing table")
    print(f"  Goal   : Poison target's routing table for {victim_node_id}")
    print(f"           by advertising a fake low-cost route through attacker")
    print("  Targets: Node mesh port 5005 (broadcast + unicast)")
    print("  Expect : HMAC FAIL → learn_indirect_routes() never called")
    print("─" * 62)

    poisoned_routing = {
        victim_node_id: {
            "next_hop"      : ATTACKER_ID,   # route through attacker
            "best_protocol" : "WiFi",
            "hop_count"     : 1,
            "avg_latency_ms": 0.5,            # impossibly good latency
            "packet_loss"   : 0.0,
            "cost"          : 0.0001,          # near-zero cost → will win
        }
    }

    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : ATTACKER_IP,
        "rssi"     : -30,                     # claim to be very close
        "routing"  : poisoned_routing,
    }
    sign_wrong(pkt)   # wrong key → dropped before learn_indirect_routes()

    udp_broadcast(UDP_MESH_PORT, pkt, "ROUTE POISONING (broadcast, wrong key)")
    udp_send(target_ip, UDP_MESH_PORT, pkt, "ROUTE POISONING (unicast, wrong key)")
    print("  Defence: verify_packet() fires before learn_indirect_routes() →")
    print("           poisoned routing table never reaches the routing logic.")
    print(f"  If key were known: attacker could redirect {victim_node_id}")
    print(f"  traffic through {ATTACKER_ID} transparently.")


# ══════════════════════════════════════════════
#  DEMO — Correctly signed HELLO PASSES
#
#  Uses the real CORRECT_KEY to demonstrate the contrast.
#  This packet will be accepted by any live node and will cause
#  NODE_DM to appear in their routing tables.
#
#  This is the "what-if the attacker knew the key" scenario.
#  It underscores why keeping SHARED_KEY = b"mesh_secret_2106"
#  out of public code is the single most important security property.
# ══════════════════════════════════════════════

def demo_valid_signed_hello(target_ip: str) -> None:
    print("\n" + "═" * 62)
    print("DEMO: Correctly signed HELLO (uses the real key for contrast)")
    print("  Goal   : Show a packet WITH the correct key IS accepted")
    print("  Moral  : All security rests on the secrecy of SHARED_KEY")
    print("─" * 62)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : "NODE_DM",      # 'demo' node — valid format, 7 chars max
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : ATTACKER_IP,
        "rssi"     : -60,
        "routing"  : {},
    }
    sign_correct(pkt)

    udp_broadcast(UDP_MESH_PORT, pkt, "VALID HELLO (broadcast, correct key)")
    udp_send(target_ip, UDP_MESH_PORT, pkt, "VALID HELLO (unicast, correct key)")
    print("  Expected: node discovers NODE_DM as a WiFi neighbour ✓")
    print("  NODE_DM will appear in routing tables and on the dashboard.")
    print("  ★ Confirms mechanism works — key secrecy is the root of trust.")


# ══════════════════════════════════════════════
#  ALSO DEMO — Correctly signed fake METRIC reaches gateway health matrix
#
#  Same "what-if" for the gateway: a signed METRIC with a fake node ID
#  will be processed by process_metric_packet() and NODE_XX will appear
#  in the dashboard health matrix.
# ══════════════════════════════════════════════

def demo_valid_signed_metric(gateway_ip: str) -> None:
    print("\n" + "═" * 62)
    print("DEMO: Correctly signed METRIC to gateway (key-compromise scenario)")
    print("  Goal   : Show that a signed metric enters the health matrix")
    print("  Moral  : Gateway trusts the key — not the node's identity")
    print("─" * 62)

    pkt = {
        "type"         : "METRIC",
        "node_id"      : "NODE_DM",
        "protocol"     : "WiFi",
        "timestamp"    : time.time(),
        "seq_number"   : 99,
        "hop_count"    : 0,
        "rssi"         : -60,
        "ip"           : ATTACKER_IP,
        "neighbours"   : [],
        "routing_table": {},
        "route_mode"   : "balanced",
        "weights"      : {"w_latency": 0.5, "w_packet_loss": 0.3, "w_power": 0.2},
        "metrics": {
            "wifi_avg_latency_ms": 25.0,
            "ble_avg_latency_ms" : 0.0,
            "wifi_packet_loss"   : 0.01,
            "ble_packet_loss"    : 0.0,
            "wifi_rssi"          : -60,
            "ble_rssi"           : -99,
            "wifi_power_cost"    : 0.25,
            "ble_power_cost"     : 0.5,
        },
    }
    sign_correct(pkt)

    udp_send(gateway_ip, UDP_GW_PORT, pkt, "VALID METRIC (correct key)")
    print("  Expected: NODE_DM appears in gateway health matrix and dashboard ✓")


# ══════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════

def print_summary() -> None:
    print("\n" + "╔" + "═" * 66 + "╗")
    print("║  ATTACK SUMMARY                                                  ║")
    print("╠" + "═" * 66 + "╣")
    rows = [
        ("1", "Unsigned HELLO (broadcast+unicast)", "DROPPED",   "Missing sig"),
        ("2", "Wrong-key HELLO (broadcast+unicast)","DROPPED",   "HMAC mismatch"),
        ("3", "Fake METRIC, no sig → gateway",      "DROPPED",   "Missing sig"),
        ("4", "Fake METRIC, wrong key → gateway",   "DROPPED",   "HMAC mismatch"),
        ("5", "ROUTE_PREF hijack, wrong key",        "DROPPED",   "HMAC mismatch"),
        ("6", "Payload tamper (impersonation)",      "DROPPED",   "HMAC mismatch"),
        ("7", "Replay attack",                       "⚠ PASSES", "No seq dedup"),
        ("8", "Fake ROUTE_PREF_ACK → gateway",       "DROPPED",   "HMAC mismatch"),
        ("9", "Route table poisoning, wrong key",    "DROPPED",   "HMAC mismatch"),
        ("D1","Valid HELLO (correct key, demo)",      "ACCEPTED",  "Correct HMAC ✓"),
        ("D2","Valid METRIC (correct key, demo)",     "ACCEPTED",  "Correct HMAC ✓"),
    ]
    for num, name, result, note in rows:
        icon = "✓" if result == "ACCEPTED" else "⚠" if "PASSES" in result else "✗"
        print(f"║  {icon} {num:<2}  {name:<42} {result:<10} {note:<12} ║")
    print("╠" + "═" * 66 + "╣")
    print("║  KNOWN GAP:                                                      ║")
    print("║  Replay attacks pass because the codebase does not deduplicate   ║")
    print("║  on (node_id, seq_number, protocol) within a time window.        ║")
    print("║  The gateway seq_tracker detects gaps but not exact duplicates.  ║")
    print("║                                                                  ║")
    print("║  RECOMMENDATION:                                                 ║")
    print("║  In gateway.py process_metric_packet(), reject any packet whose  ║")
    print("║  (node_id, seq_number) was already seen in the last 60 seconds.  ║")
    print("║  Similarly, nodes should ignore PING/PONG/HELLO with stale       ║")
    print("║  timestamps (> ROUTE_TIMEOUT seconds old).                       ║")
    print("╚" + "═" * 66 + "╝\n")


# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IoT Mesh Network – Security Attack Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target-ip",   default=DEFAULT_NODE_IP,
                        help=f"IP of a live mesh node (default: {DEFAULT_NODE_IP})")
    parser.add_argument("--gateway-ip",  default=DEFAULT_GATEWAY_IP,
                        help=f"IP of the gateway RPi (default: {DEFAULT_GATEWAY_IP})")
    parser.add_argument("--target-node", default="NODE_lx",
                        help="Node ID to target in route-level attacks (default: NODE_lx)")
    parser.add_argument("--skip-sniff",  action="store_true",
                        help="Skip the packet sniffing phase (for faster offline demo)")
    parser.add_argument("--delay",       type=float, default=1.5,
                        help="Seconds to pause between attacks (default: 1.5)")
    parser.add_argument("--demo-only",   action="store_true",
                        help="Run only the correct-key DEMO steps (no attack packets)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  IoT Mesh Network — Security Attack Demo                     ║")
    print(f"║  Target Node IP : {args.target_ip:<42}║")
    print(f"║  Gateway IP     : {args.gateway_ip:<42}║")
    print(f"║  Attack Target  : {args.target_node:<42}║")
    print(f"║  Shared Key     : {'[UNKNOWN — using wrong key for attacks]':<42}║")
    print("╚══════════════════════════════════════════════════════════════╝")

    if args.demo_only:
        print("\n[Demo-only mode — skipping all attack packets]\n")
        demo_valid_signed_hello(args.target_ip)
        time.sleep(args.delay)
        demo_valid_signed_metric(args.gateway_ip)
        print_summary()
        return

    # ── Phase 0: optional packet sniff for replay attack ─────────
    sniffed = None
    if not args.skip_sniff:
        print("\n[Phase 0] Sniffing for a real mesh packet (for replay attack)...")
        sniffed = sniff_one_packet(port=UDP_MESH_PORT, timeout=8.0)

    # ── Phase 1: all attack attempts ──────────────────────────────
    attack_unsigned_hello(args.target_ip)
    time.sleep(args.delay)

    attack_wrongkey_hello(args.target_ip)
    time.sleep(args.delay)

    attack_fake_metric_nosig(args.gateway_ip)
    time.sleep(args.delay)

    attack_fake_metric_wrongkey(args.gateway_ip)
    time.sleep(args.delay)

    attack_route_hijack(args.target_ip, target_node_id=args.target_node)
    time.sleep(args.delay)

    attack_tampered_payload(args.target_ip, target_node_id=args.target_node)
    time.sleep(args.delay)

    attack_replay(args.target_ip, sniffed)
    time.sleep(args.delay)

    attack_fake_route_pref_ack(args.gateway_ip, target_node_id=args.target_node)
    time.sleep(args.delay)

    attack_route_poisoning(args.target_ip, victim_node_id=args.target_node)
    time.sleep(args.delay)

    # ── Phase 2: demo — show what a key-compromise looks like ─────
    demo_valid_signed_hello(args.target_ip)
    time.sleep(args.delay)

    demo_valid_signed_metric(args.gateway_ip)

    # ── Final summary ─────────────────────────────────────────────
    print_summary()


if __name__ == "__main__":
    main()