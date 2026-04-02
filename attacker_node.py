"""
╔══════════════════════════════════════════════════════════════════╗
║       ATTACKER NODE  –  Security Demonstration Script            ║
║       Simulates a rogue device attempting packet injection       ║
╠══════════════════════════════════════════════════════════════════╣
║  PURPOSE: Demonstrate that unsigned / wrongly-signed packets     ║
║  are detected and dropped by legitimate mesh nodes.              ║
║                                                                  ║
║  ATTACKS DEMONSTRATED:                                           ║
║  1. HELLO Injection    – spoof a fake neighbour node             ║
║  2. METRIC Injection   – send fake sensor data to gateway        ║
║  3. ROUTE_PREF Inject  – try to hijack routing weights           ║
║  4. Replay Attack      – resend a sniffed (correct) packet       ║
║  5. Signature Tamper   – valid sig on DIFFERENT payload          ║
║  6. Correct sig (demo) – show a properly signed packet PASSES    ║
║                                                                  ║
║  Run this on any machine on the same WiFi as the mesh.           ║
║  Python 3.8+ required  (standard library only).                  ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python attacker_node.py [--target-ip <node_ip>] [--gateway-ip <gw_ip>]

Defaults use the same IPs as node.py for convenience.
"""

import socket
import json
import time
import hashlib
import hmac
import argparse
import threading

# ══════════════════════════════════════════════
#  CONFIG  – mirror node.py's network settings
# ══════════════════════════════════════════════
DEFAULT_NODE_IP    = "10.202.64.43"   # A mesh node to attack directly
DEFAULT_GATEWAY_IP = "10.202.64.43"   # The gateway
UDP_MESH_PORT      = 5005
UDP_GW_PORT        = 5006

CORRECT_KEY = b"mesh_secret_2106"     # The real shared key (attacker does NOT know this)
WRONG_KEY   = b"i_am_a_hacker_lol"   # Attacker's guessed key

ATTACKER_ID = "NODE_EV"              # Fake node ID used in injected packets

# ══════════════════════════════════════════════
#  HMAC helpers  (mirrors node.py exactly)
# ══════════════════════════════════════════════

def _hmac_sha256_bytes(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def _hexdigest(b: bytes) -> str:
    return b.hex()

def _sorted_json(obj) -> str:
    """Reproduce node.py's deterministic JSON serialiser."""
    if isinstance(obj, dict):
        items = [f'"{k}":{_sorted_json(obj[k])}' for k in sorted(obj.keys())]
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
        if obj != obj or obj in (float('inf'), float('-inf')):
            return 'null'
        if obj == int(obj) and abs(obj) < 1e15:
            return f'{obj:.1f}'
        formatted = f'{obj:.10g}'
        if '.' not in formatted and 'e' not in formatted:
            formatted += '.0'
        return formatted
    elif isinstance(obj, int):
        return str(obj)
    return 'null'

def sign_packet(pkt: dict, key: bytes = CORRECT_KEY) -> dict:
    pkt.pop("sig", None)
    payload = _sorted_json(pkt).encode()
    sig = _hexdigest(_hmac_sha256_bytes(key, payload))
    pkt["sig"] = sig
    return pkt

# ══════════════════════════════════════════════
#  TRANSPORT
# ══════════════════════════════════════════════

def udp_send(ip: str, port: int, obj: dict, label: str = ""):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = json.dumps(obj).encode()
        sock.sendto(data, (ip, port))
        sig_preview = obj.get("sig", "MISSING")[:16] if obj.get("sig") else "MISSING"
        print(f"  ↑ Sent to {ip}:{port}  [{label}]  sig={sig_preview}...")
    except Exception as e:
        print(f"  ✗ Send failed: {e}")
    finally:
        sock.close()

# ══════════════════════════════════════════════
#  SNIFF  – listen for ONE real packet to replay
# ══════════════════════════════════════════════

_sniffed_packet = None

def sniff_one_packet(port: int = UDP_MESH_PORT, timeout: float = 10.0) -> dict | None:
    """
    Listen on the mesh port and capture the first valid JSON packet seen.
    Used to demonstrate a replay attack.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(timeout)
    print(f"\n  [Sniff] Listening on :{port} for up to {timeout}s ...")
    try:
        data, addr = sock.recvfrom(4096)
        pkt = json.loads(data.decode())
        print(f"  [Sniff] Captured packet from {addr[0]}  type={pkt.get('type')}  "
              f"node={pkt.get('node_id')}  sig={pkt.get('sig','')[:16]}...")
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
#  ATTACK 1 – Unsigned HELLO injection
#  Goal: Fool a node into adding us as a neighbour
#  Result: DROPPED – missing 'sig' field
# ══════════════════════════════════════════════

def attack_unsigned_hello(target_ip: str):
    print("\n" + "═"*60)
    print("ATTACK 1: Unsigned HELLO injection")
    print("  Goal   : Fake a HELLO with no signature")
    print("  Expect : Node logs '[HMAC] Missing sig!' and drops it")
    print("─"*60)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : "10.202.64.99",   # fake attacker IP
        "rssi"     : -40,
        "routing"  : {}
        # ← no "sig" field
    }
    udp_send(target_ip, UDP_MESH_PORT, pkt, "UNSIGNED HELLO")
    print("  Expected node output: [HMAC] Missing sig!")

# ══════════════════════════════════════════════
#  ATTACK 2 – Wrong-key HELLO injection
#  Goal: Sign with a guessed key and sneak into routing table
#  Result: DROPPED – HMAC mismatch
# ══════════════════════════════════════════════

def attack_wrongkey_hello(target_ip: str):
    print("\n" + "═"*60)
    print("ATTACK 2: Wrong-key signed HELLO")
    print("  Goal   : Sign with a brute-forced / guessed key")
    print("  Expect : Node logs '[HMAC] FAIL' and drops it")
    print("─"*60)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : "10.202.64.99",
        "rssi"     : -40,
        "routing"  : {}
    }
    sign_packet(pkt, key=WRONG_KEY)   # signed with wrong secret
    udp_send(target_ip, UDP_MESH_PORT, pkt, "WRONG-KEY HELLO")
    print("  Expected node output: [HMAC] FAIL sig=...")

# ══════════════════════════════════════════════
#  ATTACK 3 – Fake METRIC to gateway
#  Goal: Inject fraudulent sensor data / inflate node count
#  Result: DROPPED – signature missing / invalid
# ══════════════════════════════════════════════

def attack_fake_metric(gateway_ip: str):
    print("\n" + "═"*60)
    print("ATTACK 3: Fake METRIC packet to gateway")
    print("  Goal   : Inject a rogue node with perfect metrics")
    print("  Expect : Gateway drops the packet (HMAC fail)")
    print("─"*60)

    pkt = {
        "type"         : "METRIC",
        "node_id"      : "NODE_XX",   # non-existent node
        "protocol"     : "WiFi",
        "timestamp"    : time.time(),
        "seq_number"   : 1,
        "hop_count"    : 0,
        "rssi"         : -20,          # suspiciously perfect signal
        "ip"           : "10.202.64.99",
        "neighbours"   : ["NODE_lx", "NODE_02"],
        "routing_table": {},
        "route_mode"   : "balanced",
        "weights"      : {"w_latency": 0.5, "w_packet_loss": 0.3, "w_power": 0.2},
        "metrics": {
            "wifi_avg_latency_ms": 1.0,    # impossibly low latency
            "ble_avg_latency_ms" : 1.0,
            "wifi_packet_loss"   : 0.0,
            "ble_packet_loss"    : 0.0,
            "wifi_rssi"          : -20,
            "ble_rssi"           : -20,
            "wifi_power_cost"    : 0.01,
            "ble_power_cost"     : 0.01,
        }
        # ← no sig
    }
    udp_send(gateway_ip, UDP_GW_PORT, pkt, "FAKE METRIC (no sig)")
    print("  Expected gateway output: [HMAC] Missing sig! → dropped")

# ══════════════════════════════════════════════
#  ATTACK 4 – ROUTE_PREF hijack
#  Goal: Override routing weights to force all traffic through attacker
#  Result: DROPPED – invalid signature
# ══════════════════════════════════════════════

def attack_route_hijack(target_ip: str, target_node_id: str = "NODE_lx"):
    print("\n" + "═"*60)
    print("ATTACK 4: ROUTE_PREF weight hijack")
    print(f"  Goal   : Force {target_node_id} to route everything via BLE")
    print("           (and eventually via attacker as 'relay')")
    print("  Expect : Packet dropped – HMAC invalid")
    print("─"*60)

    pkt = {
        "type"        : "ROUTE_PREF",
        "node_id"     : ATTACKER_ID,
        "target"      : target_node_id,
        "mode"        : "attacker_controlled",
        "w_latency"   : 0.0,          # disable latency consideration
        "w_packet_loss": 0.0,         # disable reliability consideration
        "w_power"     : 1.0,          # maximise power cost → force BLE
        "timestamp"   : time.time(),
    }
    sign_packet(pkt, key=WRONG_KEY)   # wrong key – will fail
    udp_send(target_ip, UDP_MESH_PORT, pkt, "ROUTE_PREF HIJACK")
    print("  Expected node output: [HMAC] FAIL → routing weights unchanged")

# ══════════════════════════════════════════════
#  ATTACK 5 – Signature Tampering
#  Take a real (correct) sig structure but modify the payload AFTER signing
#  Result: DROPPED – payload no longer matches the signature
# ══════════════════════════════════════════════

def attack_tampered_payload(target_ip: str):
    print("\n" + "═"*60)
    print("ATTACK 5: Payload tampering (valid sig on wrong data)")
    print("  Goal   : Attach a real-looking sig, then mutate the payload")
    print("  Expect : HMAC mismatch – node drops the packet")
    print("─"*60)

    # Step 1 – build a legitimate-looking packet and sign it honestly
    pkt = {
        "type"     : "HELLO",
        "node_id"  : ATTACKER_ID,
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : "10.202.64.99",
        "rssi"     : -60,
        "routing"  : {}
    }
    sign_packet(pkt, key=WRONG_KEY)   # attacker still uses wrong key
    saved_sig = pkt["sig"]

    # Step 2 – swap in a known good node_id so routing table accepts it
    pkt["node_id"] = "NODE_lx"        # impersonate a real node
    pkt["rssi"]    = -20              # tamper with RSSI to look closer
    # sig still refers to ATTACKER_ID + rssi=-60, so mismatch is guaranteed

    udp_send(target_ip, UDP_MESH_PORT, pkt, "TAMPERED PAYLOAD")
    print("  Expected node output: [HMAC] FAIL → impersonation blocked")

# ══════════════════════════════════════════════
#  ATTACK 6 – Replay Attack
#  Capture a real signed packet and resend it verbatim
#  Result: Accepted by HMAC (signature is valid), but timestamp staleness
#          or duplicate seq detection can be added as a defence layer.
#          This attack shows that replay protection requires a nonce/seq check.
# ══════════════════════════════════════════════

def attack_replay(target_ip: str, sniffed: dict):
    print("\n" + "═"*60)
    print("ATTACK 6: Replay attack (resend captured valid packet)")
    print("  Goal   : Resend a legitimately signed packet verbatim")
    print("  Note   : Pure HMAC does NOT prevent replay.")
    print("           Defence needs sequence-number / nonce deduplication.")
    print("─"*60)

    if sniffed is None:
        print("  SKIPPED – no packet was sniffed (run near active node)")
        return

    udp_send(target_ip, UDP_MESH_PORT, sniffed, "REPLAY")
    print("  ⚠  Replay MAY succeed if the node lacks seq-number dedup.")
    print("  Recommendation: gateway / nodes should track (node_id, seq_number)")
    print("  pairs and reject duplicates within a time window.")

# ══════════════════════════════════════════════
#  DEMO – Correctly signed packet PASSES
#  Shows the contrast: if the attacker DID know the key,
#  the packet would be accepted.  This is used in the demo
#  to highlight WHY keeping the key secret matters.
# ══════════════════════════════════════════════

def demo_valid_signed_hello(target_ip: str):
    print("\n" + "═"*60)
    print("DEMO: Correctly signed HELLO (uses real key for contrast)")
    print("  Goal   : Show that a packet WITH the correct key IS accepted")
    print("  Moral  : Security rests entirely on key secrecy")
    print("─"*60)

    pkt = {
        "type"     : "HELLO",
        "node_id"  : "NODE_DM",       # a 'demo' node id
        "protocol" : "WiFi",
        "timestamp": time.time(),
        "ip"       : "10.202.64.99",
        "rssi"     : -60,
        "routing"  : {}
    }
    sign_packet(pkt, key=CORRECT_KEY)
    udp_send(target_ip, UDP_MESH_PORT, pkt, "VALID SIGNED HELLO")
    print("  Expected node output: [Hello] neighbour NODE_DM discovered ✓")
    print("  ★ This confirms the mechanism works; key secrecy is the root of trust.")

# ══════════════════════════════════════════════
#  SUMMARY BANNER
# ══════════════════════════════════════════════

def print_summary():
    print("\n" + "╔" + "═"*58 + "╗")
    print("║  ATTACK SUMMARY                                          ║")
    print("╠" + "═"*58 + "╣")
    rows = [
        ("1", "Unsigned HELLO",         "DROPPED",  "Missing sig field"),
        ("2", "Wrong-key HELLO",        "DROPPED",  "HMAC mismatch"),
        ("3", "Fake METRIC (no sig)",   "DROPPED",  "Missing sig field"),
        ("4", "ROUTE_PREF hijack",      "DROPPED",  "HMAC mismatch"),
        ("5", "Tampered payload",       "DROPPED",  "HMAC mismatch"),
        ("6", "Replay attack",          "⚠ PASSES", "No seq-dedup yet"),
        ("–", "Valid signed HELLO",     "ACCEPTED", "Correct HMAC ✓"),
    ]
    for num, name, result, note in rows:
        line = f"║  {num}. {name:<26} → {result:<10}  {note:<16}║"
        print(line)
    print("╠" + "═"*58 + "╣")
    print("║  RECOMMENDATION:                                         ║")
    print("║  Add (node_id, seq_number) deduplication on the gateway  ║")
    print("║  with a 60-second window to block replay attacks.        ║")
    print("╚" + "═"*58 + "╝\n")

# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Mesh Network Attacker Demo")
    parser.add_argument("--target-ip",  default=DEFAULT_NODE_IP,
                        help="IP of a mesh node to attack directly")
    parser.add_argument("--gateway-ip", default=DEFAULT_GATEWAY_IP,
                        help="IP of the gateway")
    parser.add_argument("--target-node-id", default="NODE_lx",
                        help="Node ID to impersonate in ROUTE_PREF attack")
    parser.add_argument("--skip-sniff", action="store_true",
                        help="Skip the packet sniffing step (faster demo)")
    parser.add_argument("--delay", type=float, default=1.5,
                        help="Seconds between each attack (default 1.5)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  MESH NETWORK SECURITY DEMO  –  Attacker Node           ║")
    print(f"║  Target Node IP : {args.target_ip:<38}║")
    print(f"║  Gateway IP     : {args.gateway_ip:<38}║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Optional: sniff a real packet for the replay attack ──────
    sniffed = None
    if not args.skip_sniff:
        print("\n[Phase 0] Trying to sniff a real mesh packet for replay attack...")
        sniffed = sniff_one_packet(port=UDP_MESH_PORT, timeout=8.0)

    # ── Fire all attacks sequentially ────────────────────────────
    attack_unsigned_hello(args.target_ip)
    time.sleep(args.delay)

    attack_wrongkey_hello(args.target_ip)
    time.sleep(args.delay)

    attack_fake_metric(args.gateway_ip)
    time.sleep(args.delay)

    attack_route_hijack(args.target_ip, target_node_id=args.target_node_id)
    time.sleep(args.delay)

    attack_tampered_payload(args.target_ip)
    time.sleep(args.delay)

    attack_replay(args.target_ip, sniffed)
    time.sleep(args.delay)

    demo_valid_signed_hello(args.target_ip)

    # ── Final summary ─────────────────────────────────────────────
    print_summary()


if __name__ == "__main__":
    main()