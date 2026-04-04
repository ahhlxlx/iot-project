"""
╔══════════════════════════════════════════════════════════════════╗
║  ble_code.py  –  BLE layer for IoT Mesh Node (Maker Pi Pico W)  ║
║                                                                  ║
║  Responsibilities:                                               ║
║   • BLE advertisement encoding / decoding (compact 19-byte fmt) ║
║   • BLE hardware setup (scanning + advertising)                  ║
║   • IRQ handler → fills ble_rx_buffer for main loop             ║
║   • Proxy-advertising WiFi-only neighbours over BLE              ║
║   • ROUTE_PREF encoding / advertising for relay delivery         ║
║                                                                  ║
║  No imports from node_main / wifi_code – zero circular deps.    ║
║  Call setup_ble(node_id) once from node_main to initialise.     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import ubluetooth
import time
from micropython import const

# ══════════════════════════════════════════════
#  BLE PACKET TYPE CONSTANTS
# ══════════════════════════════════════════════

BLE_MAGIC                = b'\xAA\xBB'
BLE_PKT_TYPE_HELLO       = 0x01
BLE_PKT_TYPE_METRIC      = 0x02
BLE_PKT_TYPE_PING        = 0x03
BLE_PKT_TYPE_PONG        = 0x04
BLE_PKT_TYPE_ROUTE_PREF  = 0x05   # gateway → node route-weight update via BLE

# Mode byte ↔ name (used when decoding a gateway ROUTE_PREF advertisement)
_ROUTE_MODE_RMAP = {0: "balanced", 1: "latency", 2: "cost", 3: "power"}
# Name → mode byte (used when encoding a ROUTE_PREF for BLE advertisement)
_ROUTE_MODE_WMAP = {"balanced": 0, "latency": 1, "cost": 2, "power": 3}

# ══════════════════════════════════════════════
#  MODULE-LEVEL STATE
# ══════════════════════════════════════════════

ble_obj    = None
ble_active = False

# IRQ-filled receive buffer; drained by process_ble_buffer() in node_main
ble_rx_buffer = []

# Throttle print spam: print only every Nth BLE packet per node
BLE_PRINT_EVERY = 10
_ble_recv_count = {}   # { node_id: int }

# Set by setup_ble() – used by the IRQ to filter our own advertisements
_MY_NODE_ID = ""

# Dedup: gateway sends each ROUTE_PREF seq several times to fight packet loss.
# We only apply a given seq once — compare against this before buffering.
_last_route_pref_seq = -1


# ══════════════════════════════════════════════
#  BLE PACKET ENCODING / DECODING
#
#  Compact metrics in BLE manufacturer-specific advertisement data
#  (max ~20 usable bytes).
#
#  Layout (19 bytes):
#   [0-1]  magic 0xAA 0xBB
#   [2]    packet type  (HELLO / METRIC / PING / PONG)
#   [3-9]  sender NODE_ID (7 bytes ASCII, zero-padded)
#   [10]   seq/hop number (uint8, wraps at 255)
#   [11-14] timestamp low 32-bits (big-endian uint32)
#   [15]   RSSI shifted  (rssi + 128 → 0..255)
#   [16-17] latency * 10 (uint16 big-endian, max 6553.5 ms)
#   [18]   packet loss * 255 (uint8)
#
#  ROUTE_PREF layout (19 bytes):
#   [0-1]  magic 0xAA 0xBB
#   [2]    packet type  = 0x05
#   [3-9]  target NODE_ID (7 bytes ASCII, zero-padded)
#   [10]   w_latency     * 200 (uint8)
#   [11]   w_packet_loss * 200 (uint8)
#   [12]   w_power       * 200 (uint8)
#   [13]   mode byte (0=balanced 1=latency 2=cost 3=power)
#   [14]   seq (uint8, for dedup)
#   [15-18] zero padding
# ══════════════════════════════════════════════

def encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct,
               node_id_override=None):
    """
    Encode mesh metrics into a 19-byte BLE manufacturer-data payload.

    Args:
        pkt_type         : BLE_PKT_TYPE_* constant
        seq_hop          : sequence or hop counter (uint8)
        ts               : Unix timestamp (int or float)
        rssi             : current WiFi RSSI (int, dBm)
        lat_ms           : average latency in milliseconds (float)
        loss_pct         : packet-loss fraction 0.0–1.0 (float)
        node_id_override : embed a different node-id (proxy advertising)

    Returns: bytes of length 19
    """
    # MicroPython: bytes has no .ljust() – pad manually
    raw_b  = (node_id_override or _MY_NODE_ID).encode()[:7]
    node_b = raw_b + b'\x00' * (7 - len(raw_b))
    ts_int = int(ts) & 0xFFFFFFFF
    rssi_b = (rssi + 128) & 0xFF
    lat_b  = min(65535, int(lat_ms * 10))
    loss_b = min(255,   int(loss_pct * 255))
    return (BLE_MAGIC
            + bytes([pkt_type])
            + node_b
            + bytes([seq_hop & 0xFF])
            + ts_int.to_bytes(4, 'big')
            + bytes([rssi_b, (lat_b >> 8) & 0xFF, lat_b & 0xFF, loss_b]))


def encode_route_pref(target_node_id, w_latency, w_packet_loss, w_power,
                      mode, seq):
    """
    Encode a ROUTE_PREF into a 19-byte BLE manufacturer-data payload.

    This is used by:
      • The gateway (Raspberry Pi) to BLE-advertise directly to BLE-only nodes.
      • Dual-protocol relay nodes to forward a gateway ROUTE_PREF over BLE.

    Args:
        target_node_id : NODE_ID of the node that should apply these weights
        w_latency      : latency weight 0.0–1.0
        w_packet_loss  : packet-loss weight 0.0–1.0
        w_power        : power weight 0.0–1.0
        mode           : "balanced" | "latency" | "cost" | "power"
        seq            : dedup sequence number (uint8)

    Returns: bytes of length 19
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
                0, 0, 0, 0   # padding to reach 19 bytes
            ]))


def decode_ble(raw):
    """
    Decode a 19-byte manufacturer-data payload into a metric dict.

    Returns dict on success, None on malformed / short packet.
    """
    try:
        b = bytes(raw)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None

        pkt_type  = b[2]
        node_field = b[3:10].rstrip(b'\x00').decode('utf-8')

        # ── ROUTE_PREF from gateway: completely different field meanings ──
        if pkt_type == BLE_PKT_TYPE_ROUTE_PREF:
            return {
                "pkt_type"      : pkt_type,
                "target_node_id": node_field,          # [3-9] = target, not sender
                "w_latency"     : b[10] / 200.0,
                "w_packet_loss" : b[11] / 200.0,
                "w_power"       : b[12] / 200.0,
                "mode"          : _ROUTE_MODE_RMAP.get(b[13], "balanced"),
                "seq"           : b[14],
            }

        # ── Standard HELLO / METRIC / PING / PONG ──
        return {
            "pkt_type": pkt_type,
            "node_id" : node_field,
            "seq_hop" : b[10],
            "ts"      : int.from_bytes(b[11:15], 'big'),
            "rssi"    : b[15] - 128,
            "lat_ms"  : ((b[16] << 8) | b[17]) / 10.0,
            "loss"    : b[18] / 255.0
        }
    except Exception:
        return None


def find_manuf_data(adv_data):
    """
    Extract type-0xFF manufacturer data from a raw BLE advertisement blob.

    Returns the payload bytes (excluding length+type), or None.
    """
    b   = bytes(adv_data)
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


def valid_node_id(node_id):
    """
    Accept only node IDs matching our format: NODE_XX (7 chars max).
    Rejects rogue devices, junk BLE advertisers, or malformed packets.
    """
    if not node_id or len(node_id) > 7:
        return False
    if not node_id.startswith("NODE_"):
        return False
    return True


# ══════════════════════════════════════════════
#  BLE IRQ  (hardware interrupt – keep minimal)
# ══════════════════════════════════════════════

def ble_irq(event, data):
    """
    Hardware IRQ fired for every BLE scan result.
    Only appends valid mesh packets to ble_rx_buffer.
    Processing is deferred to process_ble_buffer() in node_main.

    Packet routing:
      ROUTE_PREF  – accept only if target_node_id == _MY_NODE_ID and seq is new.
                    The gateway re-sends the same seq multiple times; dedup prevents
                    applying the same weight update more than once.
      All others  – accept only if sender node_id is foreign and valid.
    """
    global _last_route_pref_seq
    _IRQ_SCAN_RESULT = const(5)
    if event == _IRQ_SCAN_RESULT:
        addr_type, addr, adv_type, rssi, adv_data = data
        manuf = find_manuf_data(adv_data)
        if manuf and len(manuf) >= 19:
            decoded = decode_ble(manuf)
            if decoded is None:
                return

            pkt_type = decoded.get("pkt_type")

            if pkt_type == BLE_PKT_TYPE_ROUTE_PREF:
                # Accept only if we are the target and it's a new seq number
                target = decoded.get("target_node_id", "")
                seq    = decoded.get("seq", -1)
                if target == _MY_NODE_ID and seq != _last_route_pref_seq:
                    _last_route_pref_seq = seq
                    ble_rx_buffer.append(decoded)

            elif (decoded.get("node_id")
                    and decoded["node_id"] != _MY_NODE_ID
                    and valid_node_id(decoded["node_id"])):
                decoded["adv_rssi"] = rssi   # RSSI as measured by our radio
                # Cap buffer size to prevent OOM when main loop is blocked
                # (e.g. during 1-second BLE relay advertising).
                # IRQ fires ~10/sec; 50 entries ≈ 5 seconds of headroom.
                if len(ble_rx_buffer) < 50:
                    ble_rx_buffer.append(decoded)


# ══════════════════════════════════════════════
#  BLE HARDWARE SETUP
# ══════════════════════════════════════════════

def setup_ble(my_node_id):
    """
    Initialise the BLE radio: start passive scanning and register IRQ.

    Args:
        my_node_id : this node's NODE_ID string (used by IRQ to self-filter)

    Sets module globals ble_obj and ble_active.
    Returns True on success, False on failure.
    """
    global ble_obj, ble_active, _MY_NODE_ID
    _MY_NODE_ID = my_node_id
    try:
        ble_obj = ubluetooth.BLE()
        ble_obj.active(True)
        ble_obj.irq(ble_irq)
        ble_obj.gap_scan(0, 100_000, 50_000, False)   # continuous passive scan
        ble_active = True
        print("[BLE]  Scanning started")
        return True
    except Exception as e:
        print(f"[BLE]  Setup failed: {e}")
        ble_obj    = None
        ble_active = False
        return False


# ══════════════════════════════════════════════
#  BLE ADVERTISING HELPERS
# ══════════════════════════════════════════════

def ble_advertise(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct):
    """
    Emit a BLE advertisement carrying our own metrics.

    Silently skips if BLE is not active.
    """
    if not ble_active or ble_obj is None:
        return
    try:
        payload = encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct)
        ad = bytes([len(payload) + 1, 0xFF]) + payload   # wrap in AD structure
        ble_obj.gap_advertise(100_000, adv_data=ad)
    except Exception as e:
        print(f"[BLE]  Advertise error: {e}")


def ble_advertise_proxy(target_node_id, pkt_type, seq_hop, ts,
                        rssi, lat_ms, loss_pct):
    """
    Advertise metrics on behalf of a WiFi-only neighbour so that
    BLE-only nodes can discover WiFi-only nodes via this dual-protocol
    relay node.

    The advertisement looks exactly like a normal BLE beacon except
    the embedded node_id is the target's, not ours.
    After a short hold (150 ms) we restore our own advertisement.

    Args:
        target_node_id : NODE_ID of the node being proxied
        pkt_type       : BLE_PKT_TYPE_* constant
        (other args)   : same as ble_advertise()
    """
    if not ble_active or ble_obj is None:
        return
    try:
        payload = encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct,
                             node_id_override=target_node_id)
        ad = bytes([len(payload) + 1, 0xFF]) + payload
        ble_obj.gap_advertise(100_000, adv_data=ad)
        time.sleep(0.15)    # hold long enough for a nearby scanner to catch it

        # Restore our own advertisement so we don't disappear from neighbours
        own_payload = encode_ble(BLE_PKT_TYPE_HELLO, 0, ts, rssi, lat_ms, loss_pct)
        own_ad = bytes([len(own_payload) + 1, 0xFF]) + own_payload
        ble_obj.gap_advertise(100_000, adv_data=own_ad)
    except Exception as e:
        print(f"[BLE]  Proxy advertise error for {target_node_id}: {e}")


def ble_advertise_route_pref(target_node_id, w_latency, w_packet_loss,
                             w_power, mode, seq, repeat=3, hold_ms=200):
    """
    BLE-advertise a ROUTE_PREF on behalf of the gateway.

    Used by dual-protocol relay nodes to deliver routing-weight updates
    to BLE-only neighbours that the gateway cannot reach via UDP.

    The advertisement is repeated `repeat` times with `hold_ms` between
    each burst, then the node's own HELLO advertisement is restored.

    Args:
        target_node_id : NODE_ID of the BLE-only target node
        w_latency      : latency weight (0.0–1.0)
        w_packet_loss  : packet-loss weight (0.0–1.0)
        w_power        : power weight (0.0–1.0)
        mode           : "balanced" | "latency" | "cost" | "power"
        seq            : dedup sequence (uint8)
        repeat         : number of advertisement bursts (default 3)
        hold_ms        : milliseconds to hold each burst (default 200)
    """
    if not ble_active or ble_obj is None:
        print(f"[BLE]  Cannot relay ROUTE_PREF for {target_node_id}: BLE not active")
        return False
    try:
        payload = encode_route_pref(target_node_id, w_latency, w_packet_loss,
                                    w_power, mode, seq)
        ad = bytes([len(payload) + 1, 0xFF]) + payload

        for i in range(repeat):
            ble_obj.gap_advertise(100_000, adv_data=ad)
            time.sleep(hold_ms / 1000.0)

        # Restore our own HELLO advertisement
        ts   = time.time()
        rssi = -70   # placeholder; will be overwritten next HELLO cycle
        own_payload = encode_ble(BLE_PKT_TYPE_HELLO, 0, ts, rssi, 0.0, 0.0)
        own_ad = bytes([len(own_payload) + 1, 0xFF]) + own_payload
        ble_obj.gap_advertise(100_000, adv_data=own_ad)

        print(f"[BLE]  ROUTE_PREF relayed for {target_node_id}: "
              f"mode={mode} seq={seq} (×{repeat})")
        return True
    except Exception as e:
        print(f"[BLE]  ROUTE_PREF relay error for {target_node_id}: {e}")
        return False