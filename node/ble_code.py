"""
╔══════════════════════════════════════════════════════════════════╗
║  ble_code.py  –  BLE layer for IoT Mesh Node (Maker Pi Pico W)  ║
║                                                                  ║
║  Security: ROUTE_PREF packets carry a 4-byte truncated HMAC     ║
║  in bytes [15-18], computed over bytes [0-14] with the shared   ║
║  key. This prevents rogue BLE devices from injecting fake       ║
║  routing weight updates (1-in-4-billion brute-force odds).      ║
║                                                                  ║
║  Call setup_ble(node_id, shared_key) from node_main to init.    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import ubluetooth
import time
import hashlib
from micropython import const

# ══════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════

BLE_MAGIC                = b'\xAA\xBB'
BLE_PKT_TYPE_HELLO       = 0x01
BLE_PKT_TYPE_METRIC      = 0x02
BLE_PKT_TYPE_PING        = 0x03
BLE_PKT_TYPE_PONG        = 0x04
BLE_PKT_TYPE_ROUTE_PREF  = 0x05
BLE_PKT_TYPE_PROXY       = 0x06  # WiFi-only node relayed over BLE by a dual-proto neighbour

_ROUTE_MODE_RMAP = {0: "balanced", 1: "latency", 2: "cost", 3: "power"}
_ROUTE_MODE_WMAP = {"balanced": 0, "latency": 1, "cost": 2, "power": 3}

# ══════════════════════════════════════════════
#  MODULE STATE
# ══════════════════════════════════════════════

ble_obj    = None
ble_active = False
ble_rx_buffer = []

BLE_PRINT_EVERY = 10
_ble_recv_count = {}
_MY_NODE_ID     = ""
_SHARED_KEY     = b""      # Set by setup_ble(); HMAC key for ROUTE_PREF
_last_route_pref_seq = -1

# ══════════════════════════════════════════════
#  4-BYTE TRUNCATED HMAC  (BLE ROUTE_PREF security)
# ══════════════════════════════════════════════

def _hmac4(key, msg):
    """First 4 bytes of HMAC-SHA256. Pure MicroPython."""
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key  = key + b'\x00' * (block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hashlib.sha256(ipad + msg).digest()
    full  = hashlib.sha256(opad + inner).digest()
    return full[:4]


def verify_ble_hmac(raw_15, received_mac4):
    """Verify 4-byte HMAC on a ROUTE_PREF packet. True if valid or no key."""
    if not _SHARED_KEY:
        return True
    expected = _hmac4(_SHARED_KEY, bytes(raw_15))
    return expected == bytes(received_mac4)


# ══════════════════════════════════════════════
#  ENCODING / DECODING
#
#  ROUTE_PREF layout (19 bytes):
#   [0-1]   magic 0xAA 0xBB
#   [2]     type 0x05
#   [3-9]   target NODE_ID (7 bytes, zero-padded)
#   [10]    w_latency × 200
#   [11]    w_packet_loss × 200
#   [12]    w_power × 200
#   [13]    mode byte
#   [14]    seq (uint8)
#   [15-18] HMAC-SHA256(key, [0:15])[:4]
# ══════════════════════════════════════════════

def encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct,
               node_id_override=None):
    """Encode mesh metrics into a 19-byte BLE payload."""
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
    """Encode ROUTE_PREF with 4-byte truncated HMAC in bytes [15-18]."""
    raw_b  = target_node_id.encode()[:7]
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
    mac4 = _hmac4(_SHARED_KEY, data_15) if _SHARED_KEY else b'\x00\x00\x00\x00'
    return data_15 + mac4


def decode_ble(raw):
    """Decode 19-byte BLE payload. Returns dict or None."""
    try:
        b = bytes(raw)
        if len(b) < 19 or b[0:2] != BLE_MAGIC:
            return None
        pkt_type   = b[2]
        node_field = b[3:10].rstrip(b'\x00').decode('utf-8')
        if pkt_type == BLE_PKT_TYPE_ROUTE_PREF:
            return {
                "pkt_type"      : pkt_type,
                "target_node_id": node_field,
                "w_latency"     : b[10] / 200.0,
                "w_packet_loss" : b[11] / 200.0,
                "w_power"       : b[12] / 200.0,
                "mode"          : _ROUTE_MODE_RMAP.get(b[13], "balanced"),
                "seq"           : b[14],
                "_raw_15"       : b[0:15],
                "_mac4"         : b[15:19],
            }
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
    """Extract type-0xFF manufacturer data from raw BLE adv blob."""
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
    if not node_id or len(node_id) > 7:
        return False
    return node_id.startswith("NODE_")


# ══════════════════════════════════════════════
#  BLE IRQ
# ══════════════════════════════════════════════

def ble_irq(event, data):
    """IRQ handler. HMAC check deferred to process_ble_buffer (keep IRQ fast)."""
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
                target = decoded.get("target_node_id", "")
                seq    = decoded.get("seq", -1)
                if target == _MY_NODE_ID and seq != _last_route_pref_seq:
                    _last_route_pref_seq = seq
                    ble_rx_buffer.append(decoded)
            elif (decoded.get("node_id")
                    and decoded["node_id"] != _MY_NODE_ID
                    and valid_node_id(decoded["node_id"])):
                decoded["adv_rssi"] = rssi
                if len(ble_rx_buffer) < 50:
                    ble_rx_buffer.append(decoded)


# ══════════════════════════════════════════════
#  BLE SETUP
# ══════════════════════════════════════════════

def setup_ble(my_node_id, shared_key=b""):
    """Init BLE radio with optional HMAC key for ROUTE_PREF security."""
    global ble_obj, ble_active, _MY_NODE_ID, _SHARED_KEY
    _MY_NODE_ID = my_node_id
    _SHARED_KEY = shared_key
    try:
        ble_obj = ubluetooth.BLE()
        ble_obj.active(True)
        ble_obj.irq(ble_irq)
        ble_obj.gap_scan(0, 100_000, 50_000, False)
        ble_active = True
        hmac_str = "HMAC-enabled" if shared_key else "no-HMAC"
        print(f"[BLE]  Scanning started ({hmac_str})")
        return True
    except Exception as e:
        print(f"[BLE]  Setup failed: {e}")
        ble_obj    = None
        ble_active = False
        return False


# ══════════════════════════════════════════════
#  BLE ADVERTISING
# ══════════════════════════════════════════════

def ble_advertise(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct):
    if not ble_active or ble_obj is None:
        return
    try:
        payload = encode_ble(pkt_type, seq_hop, ts, rssi, lat_ms, loss_pct)
        ad = bytes([len(payload) + 1, 0xFF]) + payload
        ble_obj.gap_advertise(100_000, adv_data=ad)
    except Exception as e:
        print(f"[BLE]  Advertise error: {e}")


def ble_advertise_proxy(target_node_id, pkt_type, seq_hop, ts,
                        rssi, lat_ms, loss_pct):
    if not ble_active or ble_obj is None:
        return
    try:
        # Use BLE_PKT_TYPE_PROXY (not caller's pkt_type) so receivers know
        # this is a relayed packet and must NOT create a direct link to
        # target_node_id – the real next hop is this advertising node.
        payload = encode_ble(BLE_PKT_TYPE_PROXY, seq_hop, ts, rssi, lat_ms, loss_pct,
                             node_id_override=target_node_id)
        ad = bytes([len(payload) + 1, 0xFF]) + payload
        ble_obj.gap_advertise(100_000, adv_data=ad)
        time.sleep(0.15)
        own_payload = encode_ble(BLE_PKT_TYPE_HELLO, 0, ts, rssi, lat_ms, loss_pct)
        own_ad = bytes([len(own_payload) + 1, 0xFF]) + own_payload
        ble_obj.gap_advertise(100_000, adv_data=own_ad)
    except Exception as e:
        print(f"[BLE]  Proxy advertise error for {target_node_id}: {e}")


def ble_advertise_route_pref(target_node_id, w_latency, w_packet_loss,
                             w_power, mode, seq, repeat=3, hold_ms=200):
    """BLE-advertise ROUTE_PREF with HMAC for a BLE-only target."""
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
        ts   = time.time()
        own_payload = encode_ble(BLE_PKT_TYPE_HELLO, 0, ts, -70, 0.0, 0.0)
        own_ad = bytes([len(own_payload) + 1, 0xFF]) + own_payload
        ble_obj.gap_advertise(100_000, adv_data=own_ad)
        print(f"[BLE]  ROUTE_PREF relayed for {target_node_id}: "
              f"mode={mode} seq={seq} HMAC={'yes' if _SHARED_KEY else 'no'}")
        return True
    except Exception as e:
        print(f"[BLE]  ROUTE_PREF relay error for {target_node_id}: {e}")
        return False