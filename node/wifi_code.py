"""
╔══════════════════════════════════════════════════════════════════╗
║  wifi_code.py  –  WiFi layer for IoT Mesh Node (Maker Pi Pico W)║
║                                                                  ║
║  Responsibilities:                                               ║
║   • WiFi connection management (connect, reconnect, RSSI)        ║
║   • UDP socket lifecycle (setup, non-blocking recv)              ║
║   • UDP send helpers (unicast + broadcast)                       ║
║                                                                  ║
║  No imports from node_main / ble_code – zero circular deps.     ║
║  Call connect_wifi() and setup_udp() from node_main on boot.    ║
╚══════════════════════════════════════════════════════════════════╝
"""

import network
import socket
import json
import time

# ══════════════════════════════════════════════
#  MODULE-LEVEL STATE
# ══════════════════════════════════════════════

wlan        = None          # network.WLAN handle
udp_sock    = None          # non-blocking UDP socket
wifi_active = False         # True once WiFi is connected and socket is open
my_ip       = "0.0.0.0"    # our assigned IP address

# Set once by connect_wifi(); reused by check_wifi_reconnect()
_SSID     = ""
_PASSWORD = ""

# Mesh port stored by setup_udp(); reused when reopening the socket
_MESH_PORT = 5005


# ══════════════════════════════════════════════
#  WiFi CONNECTION
# ══════════════════════════════════════════════

def connect_wifi(ssid, password, timeout_s=20):
    """
    Blocking WiFi connect.  Tries for up to timeout_s seconds.

    Args:
        ssid       : SSID of the shared mesh network
        password   : WPA2 passphrase
        timeout_s  : seconds to wait before giving up (default 20)

    Sets module globals wlan, my_ip, wifi_active.
    Returns True on success, False on failure.
    """
    global wlan, my_ip, wifi_active, _SSID, _PASSWORD
    _SSID     = ssid
    _PASSWORD = password

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(ssid, password)
    print(f"[WiFi] Connecting to '{ssid}' ...")

    for _ in range(timeout_s):
        if wlan.isconnected():
            break
        time.sleep(1)

    if wlan.isconnected():
        my_ip       = wlan.ifconfig()[0]
        wifi_active = True
        print(f"[WiFi] Connected  IP={my_ip}")
        return True

    wifi_active = False
    print("[WiFi] FAILED – running in BLE-only mode")
    return False


def wifi_rssi():
    """
    Return the current WiFi RSSI in dBm, or -99 if unavailable.
    Safe to call even if WiFi is disconnected.
    """
    try:
        if wifi_active and wlan and wlan.isconnected():
            return wlan.status('rssi')
    except Exception:
        pass
    return -99


def check_wifi_reconnect():
    """
    Non-blocking WiFi reconnect trigger.

    Checks if a previous background connect attempt succeeded; if so,
    promotes the state.  If still disconnected, fires a new connect()
    call (returns immediately – result checked on next call cycle).

    BLE operation is NOT paused during this call.
    """
    global wifi_active, udp_sock, my_ip

    if wifi_active and wlan and wlan.isconnected():
        return   # all good

    # Check whether a previously triggered attempt succeeded
    if wlan and wlan.isconnected():
        my_ip       = wlan.ifconfig()[0]
        wifi_active = True
        if udp_sock is None:
            setup_udp(_MESH_PORT)
        print(f"[WiFi] Reconnected  IP={my_ip}")
        return

    # Trigger a fresh non-blocking attempt
    try:
        print("[WiFi] Attempting reconnect (background)...")
        wlan.connect(_SSID, _PASSWORD)
        # Don't wait here – result checked on next retry cycle
    except Exception as e:
        print(f"[WiFi] Reconnect trigger error: {e}")


# ══════════════════════════════════════════════
#  UDP SOCKET
# ══════════════════════════════════════════════

def setup_udp(mesh_port):
    """
    Open a non-blocking UDP socket bound to mesh_port on all interfaces.

    Args:
        mesh_port : UDP_MESH_PORT constant from node_main

    Sets module global udp_sock.
    Silently skips if WiFi is not yet active.
    """
    global udp_sock, _MESH_PORT
    _MESH_PORT = mesh_port

    if not wifi_active:
        print("[UDP]  Skipped – no WiFi")
        return
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.bind(("0.0.0.0", mesh_port))
        udp_sock.setblocking(False)
        print(f"[UDP]  Listening on port {mesh_port}")
    except Exception as e:
        print(f"[UDP]  Setup failed: {e}")
        udp_sock = None


def udp_send(ip, port, obj):
    """
    Serialise obj as JSON and send to (ip, port) via the mesh socket.

    Detects WiFi drop on send failure and clears wifi_active so the
    main loop can schedule a reconnect.

    Returns True on success, False on failure.
    """
    global wifi_active
    if not wifi_active or udp_sock is None:
        return False
    try:
        udp_sock.sendto(json.dumps(obj).encode(), (ip, port))
        return True
    except Exception as e:
        print(f"[UDP]  Send error: {e}")
        # Detect WiFi drop immediately via send failure rather than
        # waiting up to WIFI_RETRY_INTERVAL seconds.
        if wlan and not wlan.isconnected():
            wifi_active = False
            print("[WiFi] Disconnected — detected via send failure")
        return False


def udp_broadcast(port, obj):
    """
    Serialise obj as JSON and send a UDP broadcast to 255.255.255.255:port.

    Opens a temporary socket with SO_BROADCAST so the main mesh socket
    can remain bound to a specific port.

    Returns True on success, False on failure.
    """
    if not wifi_active or udp_sock is None:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(json.dumps(obj).encode(), ("255.255.255.255", port))
        s.close()
        return True
    except Exception as e:
        print(f"[UDP]  Broadcast error: {e}")
        return False
