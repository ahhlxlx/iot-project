"""
mesh_node_ble_test.py — BLE-only test for Maker Pi Pico W

Strips out WiFi and LoRa completely.
Only tests:
  - BLE advertising as MeshNode_0x04
  - BLE GATT notifications (sending Hello + Data to gateway)
  - BLE IRQ (connect / disconnect / write from gateway)
  - Re-advertising after disconnect

Flash this to the Pico, run gateway.py on the Pi, and confirm:
  [BLE] Subscribed to notifications from MeshNode_0x04
  [BLE] DATA src=4 seq=X hops=1 latency=Xms path=[4]
appear in the gateway log.
"""

import time
import json
import utime
import bluetooth

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← change NODE_ID per device before flashing
# ─────────────────────────────────────────────────────────────────────────────
NODE_ID          = 0x04
GATEWAY_ID       = 0xFF
PROTOCOL_BLE     = 1

BLE_NAME         = f"MeshNode_{NODE_ID:#04x}"

HELLO_INTERVAL   = 5     # seconds between Hello broadcasts
PACKET_INTERVAL  = 2     # seconds between data sends
MAX_SEQ          = 65535
# ─────────────────────────────────────────────────────────────────────────────


# ── Shared state ─────────────────────────────────────────────────────────────
seq_num               = 0
ble                   = bluetooth.BLE()
ble_enabled           = False
_ble_connections      = {}
_ble_char_handle      = None
_ble_reconnect_needed = False
# ─────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def next_seq():
    global seq_num
    seq_num = (seq_num + 1) % MAX_SEQ
    return seq_num


def build_hello_payload():
    return json.dumps({
        "type"     : "HELLO",
        "node_id"  : NODE_ID,
        "protocol" : PROTOCOL_BLE,
        "timestamp": utime.ticks_ms(),
    })


def build_data_payload(seq):
    return json.dumps({
        "type"        : "DATA",
        "src_id"      : NODE_ID,
        "dest_id"     : GATEWAY_ID,
        "seq_num"     : seq,
        "protocol"    : PROTOCOL_BLE,
        "hop_count"   : 1,
        "path"        : [NODE_ID],
        "send_time_ms": utime.ticks_ms(),
        "rssi"        : 0,
    })


# ══════════════════════════════════════════════════════════════════════════════
# BLE
# ══════════════════════════════════════════════════════════════════════════════

def _ble_build_adv_data():
    return (bytearray(b'\x02\x01\x06') +
            bytearray([len(BLE_NAME) + 1, 0x09]) +
            BLE_NAME.encode())


def ble_setup():
    global ble_enabled, _ble_char_handle
    try:
        ble.active(True)
        ble.config(gap_name=BLE_NAME)
        ble.irq(ble_irq)

        _FLAG_READ   = 0x0002
        _FLAG_WRITE  = 0x0008
        _FLAG_NOTIFY = 0x0010
        services = (
            (bluetooth.UUID(0xFEAA), (
                (bluetooth.UUID(0x2A56), _FLAG_READ | _FLAG_WRITE | _FLAG_NOTIFY),
            )),
        )
        ((handle,),) = ble.gatts_register_services(services)
        _ble_char_handle = handle

        ble.gap_advertise(100_000, _ble_build_adv_data())
        ble_enabled = True
        print(f"[BLE] Advertising as '{BLE_NAME}'")

    except Exception as e:
        print(f"[BLE] Setup failed: {e}")


def ble_irq(event, data):
    """
    BLE IRQ — only sets flags, never calls ble.*() directly.
    Re-advertising is handled safely in the main loop.
    """
    global _ble_reconnect_needed

    _IRQ_CENTRAL_CONNECT    = 1
    _IRQ_CENTRAL_DISCONNECT = 2
    _IRQ_GATTS_WRITE        = 3

    try:
        if event == _IRQ_CENTRAL_CONNECT:
            conn_handle, _, _ = data
            _ble_connections[conn_handle] = True
            print(f"[BLE] Connected  handle={conn_handle}  peers={len(_ble_connections)}")

        elif event == _IRQ_CENTRAL_DISCONNECT:
            conn_handle, _, _ = data
            _ble_connections.pop(conn_handle, None)
            _ble_reconnect_needed = True
            print(f"[BLE] Disconnected handle={conn_handle} — will re-advertise")

        elif event == _IRQ_GATTS_WRITE:
            conn_handle, value_handle = data
            try:
                raw = ble.gatts_read(value_handle)
                msg = json.loads(raw.decode())
                mtype = msg.get("type", "?")
                print(f"[BLE] Received {mtype} from handle={conn_handle}")
            except Exception as e:
                print(f"[BLE] IRQ parse error: {e}")

    except Exception as e:
        print(f"[BLE] IRQ error event={event}: {e}")


def ble_send_hello():
    if not ble_enabled or not _ble_char_handle:
        return
    payload = build_hello_payload().encode()
    sent = 0
    for conn_handle in list(_ble_connections.keys()):
        try:
            ble.gatts_notify(conn_handle, _ble_char_handle, payload)
            sent += 1
        except Exception as e:
            print(f"[BLE] Hello notify error handle={conn_handle}: {e}")
            _ble_connections.pop(conn_handle, None)
    print(f"[BLE] Hello sent to {sent} peer(s)")


def ble_send_data():
    if not ble_enabled or not _ble_char_handle:
        return
    if not _ble_connections:
        print("[BLE] No connections — skipping data send")
        return
    seq     = next_seq()
    payload = build_data_payload(seq).encode()[:512]
    sent    = 0
    for conn_handle in list(_ble_connections.keys()):
        try:
            ble.gatts_notify(conn_handle, _ble_char_handle, payload)
            sent += 1
        except Exception as e:
            print(f"[BLE] Data notify error handle={conn_handle}: {e}")
            _ble_connections.pop(conn_handle, None)
    if sent:
        print(f"[BLE] Data seq={seq} → Gateway ({sent} peer(s))")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global _ble_reconnect_needed

    print(f"[Node] BLE-only test  node={NODE_ID:#04x}")
    ble_setup()
    print("[Node] Running...\n")

    last_hello  = 0
    last_packet = 0

    while True:
        now = time.time()

        # Re-advertise after disconnect (safe outside IRQ)
        if _ble_reconnect_needed:
            _ble_reconnect_needed = False
            try:
                ble.gap_advertise(100_000, _ble_build_adv_data())
                print("[BLE] Re-advertising after disconnect")
            except Exception as e:
                print(f"[BLE] Re-advertise error: {e}")

        # Hello broadcast
        if now - last_hello >= HELLO_INTERVAL:
            ble_send_hello()
            last_hello = now

        # Data packet
        if now - last_packet >= PACKET_INTERVAL:
            ble_send_data()
            last_packet = now

        time.sleep(0.05)


if __name__ == "__main__":
    main()