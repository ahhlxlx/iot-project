"""
╔══════════════════════════════════════════════════════════════════╗
║  ble_code.py  –  BLE layer for IoT Mesh Node (Maker Pi Pico W)  ║
║                                                                  ║
║  Responsibilities:                                               ║
║   • BLE advertisement encoding / decoding (compact 19-byte fmt) ║
║   • BLE hardware setup (scanning + advertising)                  ║
║   • IRQ handler → fills ble_rx_buffer for main loop             ║
║   • Proxy-advertising WiFi-only neighbours over BLE              ║
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

BLE_MAGIC           = b'\xAA\xBB'
BLE_PKT_TYPE_HELLO  = 0x01
BLE_PKT_TYPE_METRIC = 0x02
BLE_PKT_TYPE_PING   = 0x03
BLE_PKT_TYPE_PONG   = 0x04

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


def decode_ble(raw):
    """
    Decode a 19-byte manufacturer-data payload into a metric dict.

    Returns dict on success, None on malformed / short packet.
    """
    try:
        b = bytes(raw)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None
        return {
            "pkt_type": b[2],
            "node_id" : b[3:10].rstrip(b'\x00').decode('utf-8'),
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
    Only appends valid, foreign mesh packets to ble_rx_buffer.
    Processing is deferred to process_ble_buffer() in node_main.
    """
    _IRQ_SCAN_RESULT = const(5)
    if event == _IRQ_SCAN_RESULT:
        addr_type, addr, adv_type, rssi, adv_data = data
        manuf = find_manuf_data(adv_data)
        if manuf and len(manuf) >= 19:
            decoded = decode_ble(manuf)
            if (decoded
                    and decoded["node_id"]
                    and decoded["node_id"] != _MY_NODE_ID
                    and valid_node_id(decoded["node_id"])):
                decoded["adv_rssi"] = rssi   # RSSI as measured by our radio
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
