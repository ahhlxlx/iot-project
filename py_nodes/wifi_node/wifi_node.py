"""
py_nodes/wifi_node/wifi_node.py
WiFi Node for Maker Pi Pico W
- Connects to WiFi
- Broadcasts Hello messages to discover neighbours
- Sends data packets to Gateway and other nodes via UDP
- Listens for incoming packets from other nodes
- Maintains routing table and metrics
"""
 
import network
import socket
import time
import json
import _thread
import utime
import sys
 
# ── adjust sys.path so shared modules are found ───────
sys.path.append('/Project')
 
from metrics import Metrics
from packet_format import Packet
from routing_table import RoutingTable
 
# ───────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────
WIFI_SSID       = "lixuan"
WIFI_PASSWORD   = "testTest"
 
NODE_ID         = 0x02          # Unique ID for this node  (0x01, 0x02, 0x03 …)
GATEWAY_ID      = 0xFF          # Reserved ID for the gateway
PROTOCOL_WIFI   = 2             # As defined in packet_format.py
 
GATEWAY_IP      = "172.20.10.4" # Static IP of your Raspberry Pi gateway
BROADCAST_IP    = "255.255.255.255" # UDP broadcast address for Hello messages
 
UDP_PORT        = 5005          # All nodes + gateway listen on this port
HELLO_INTERVAL  = 5             # Seconds between Hello broadcasts
PACKET_INTERVAL = 2             # Seconds between data packet transmissions
MAX_SEQ         = 65535         # Sequence number wraps here
 
# ────────── Shared state ───────────────────────
metrics = Metrics()
routing_table = RoutingTable()
seq_num = 0
lock = _thread.allocate_lock()   # Protect seq_num across threads

def connect_wifi():
    """Connect to WiFi and return the assigned IP address."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(WIFI_SSID, WIFI_PASSWORD)
    print(f"[WiFi] Connecting to {WIFI_SSID} ", end="")
    timeout = 15
    while not wlan.isconnected() and timeout > 0:
        print(".", end="")
        time.sleep(1)
        timeout -= 1
    if not wlan.isconnected():
        raise OSError("[WiFi] Failed to connect – check SSID / password")
    ip = wlan.ifconfig()[0]
    print(f"\n[WiFi] Connected  IP={ip}")
    return ip
 
def build_hello(my_ip):
    """Return a JSON-encoded Hello message."""
    return json.dumps({
        "type" : "HELLO",
        "node_id" : NODE_ID,
        "protocol" : PROTOCOL_WIFI,
        "ip" : my_ip,
        "timestamp": int(time.time() * 1000),
    }).encode()
 
def build_data_packet(pkt: Packet, rssi: int = 0):
    """Serialise a Packet to JSON bytes."""
    return json.dumps({
        "type" : "DATA",
        "src_id" : pkt.src_id,
        "dest_id" : pkt.dest_id,
        "seq_num" : pkt.seq_num,
        "protocol" : pkt.protocol,
        "hop_count" : pkt.hop_count,
        "path" : pkt.path,
        "send_time_ms": pkt.send_time_ms,
        "rssi" : rssi,
    }).encode()

def send_udp(sock, data: bytes, ip: str, port: int):
    """Send bytes over UDP, swallowing transient errors."""
    try:
        sock.sendto(data, (ip, port))
    except OSError as e:
        print(f"[UDP] Send error → {ip}:{port}  {e}")

def broadcast_hello(sock, my_ip: str):
    """Broadcast a Hello message so neighbours can discover us."""
    msg = build_hello(my_ip)
    send_udp(sock, msg, BROADCAST_IP, UDP_PORT)
    print(f"[Hello] Broadcast sent from Node {NODE_ID:#04x}")

def send_data_to_gateway(sock):
    """Create a new data packet and send it to the gateway."""
    global seq_num
    with lock:
        seq_num = (seq_num + 1) % MAX_SEQ
        current_seq = seq_num
    pkt = Packet(
        src_id = NODE_ID,
        dest_id = GATEWAY_ID,
        seq_num = current_seq,
        protocol = PROTOCOL_WIFI,
    )
    pkt.hop_count = 1
    pkt.path      = [NODE_ID]
    pkt.send_time_ms = utime.ticks_ms()
    metrics.record_send(current_seq)
    payload = build_data_packet(pkt)
    send_udp(sock, payload, GATEWAY_IP, UDP_PORT)
    print(f"[Data] Sent seq={current_seq} → Gateway")
 
 
def forward_to_best_hop(sock, raw_msg: dict):
    """
    If a packet is not destined for us, find the best next hop
    from our routing table and forward it.
    """
    best_hop = routing_table.select_best_next_hop()
    if best_hop == 0xFF:
        print("[Route] No neighbours – dropping packet")
        return
 
    # Look up the IP of the best hop (stored when we received its Hello)
    hop_ip = routing_table.entries[best_hop].neighbor_id  # reused field = IP string
    raw_msg["hop_count"] = raw_msg.get("hop_count", 0) + 1
    raw_msg["path"] = raw_msg.get("path", []) + [NODE_ID]
    send_udp(sock, json.dumps(raw_msg).encode(), hop_ip, UDP_PORT)
    print(f"[Route] Forwarded seq={raw_msg.get('seq_num')} → {hop_ip}")
 
def handle_incoming(sock):
    """
    Listener thread – runs forever, processes Hello and Data packets.
    Stores recv_time in metrics; updates routing table from Hello messages.
    """
    while True:
        try:
            data, addr = sock.recvfrom(512)
            msg = json.loads(data.decode())
            sender_ip = addr[0]
            if msg["type"] == "HELLO":
                neighbor_id = msg["node_id"]
                # Use IP string as the "neighbor_id" key so we can look it up later
                routing_table.update_route(
                    neighbor_id = neighbor_id,
                    avg_latency = 0,
                    rssi = 0,
                    power_cost = 1,
                )
                print(f"[Hello] Received from Node {neighbor_id:#04x}  IP={sender_ip}")
            elif msg["type"] == "DATA":
                dest = msg.get("dest_id")
                if dest == NODE_ID:
                    # Packet is for us – record arrival
                    seq  = msg.get("seq_num", -1)
                    recv = int(time.time() * 1000)
                    metrics.record_receive(seq, recv)
                    latency = recv - msg.get("send_time_ms", recv)
                    print(f"[Data] Received seq={seq}  latency={latency}ms  from={sender_ip}")
 
                    # Update routing table with measured latency
                    src = msg.get("src_id")
                    if src in routing_table.entries:
                        entry = routing_table.entries[src]
                        routing_table.update_route(
                            neighbor_id = src,
                            avg_latency = metrics.calculate_average_latency(),
                            rssi = msg.get("rssi", 0),
                            power_cost = entry.power_cost,
                        )
                elif dest == GATEWAY_ID:
                    # Not our packet – forward toward gateway
                    forward_to_best_hop(sock, msg)
            elif msg["type"] == "ACK":
                sent = msg.get("send_time_ms", 0)
                latency = utime.ticks_diff(utime.ticks_ms(), sent)
                seq = msg.get("seq_num", -1)
                metrics.record_receive(seq)
                print(f"[ACK]  seq={seq}  latency={latency}ms")
        except OSError:
            # Socket timeout – perfectly normal, just loop
            pass
        except Exception as e:
            print(f"[Listener] Error: {e}")

def main():
    my_ip = connect_wifi()
 
    # ────────────────── UDP socket ─────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    sock.settimeout(0.5)   # Non-blocking-ish so the listener can loop quickly
 
    # Start listener on second core
    _thread.start_new_thread(handle_incoming, (sock,))
    print(f"[Node] WiFi Node {NODE_ID:#04x} running on {my_ip}")
    last_hello  = 0
    last_packet = 0
 
    while True:
        now = time.time()
        if now - last_hello >= HELLO_INTERVAL:
            broadcast_hello(sock, my_ip)
            last_hello = now
        if now - last_packet >= PACKET_INTERVAL:
            send_data_to_gateway(sock)
            last_packet = now
        time.sleep(0.1)

# ────────── Entry point ──────────────
if __name__ == "__main__":
    main()