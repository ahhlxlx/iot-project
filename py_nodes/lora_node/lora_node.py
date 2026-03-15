import serial
import serial.tools.list_ports
import time
import json
import sys
import os
import datetime
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from CommonNodeCode.metrics import Metrics
from CommonNodeCode.packet_format import Packet
from CommonNodeCode.routing_table import RoutingTable

# ─── Config ───────────────────────────────────────────────────────────────────
NODE_ID          = "LORA_A"
DEST_ID          = "GATEWAY"
PROTOCOL_LORA    = 3
SEND_INTERVAL    = 5
HELLO_INTERVAL   = 5
SUMMARY_INTERVAL = 30
BAUD_RATE        = 9600
MAX_SEQ          = 65535
LOG_FILE         = "lora_log.json"
# ──────────────────────────────────────────────────────────────────────────────

metrics       = Metrics()
routing_table = RoutingTable()
log_entries   = []
seq_lock      = threading.Lock()
seq_num       = 0

# ─── Logging ──────────────────────────────────────────────────────────────────
def log_packet(entry: dict):
    entry["timestamp"] = datetime.datetime.now().isoformat()
    log_entries.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(log_entries, f, indent=2)

# ─── Serial helpers ───────────────────────────────────────────────────────────
def find_port():
    ports = serial.tools.list_ports.comports()
    for p in ports:
        if any(kw in p.description for kw in ["Arduino", "CH340", "USB Serial", "ttyUSB", "ttyACM"]):
            print(f"[Auto-detected] {p.device} — {p.description}")
            return p.device
    print("[!] Could not auto-detect port. Available ports:")
    for p in ports:
        print(f"    {p.device} — {p.description}")
    return input("Enter port manually (e.g. COM3 or /dev/ttyUSB0): ").strip()

def connect_serial(port, baud):
    while True:
        try:
            ser = serial.Serial(port, baud, timeout=1)
            print(f"[Serial] Connected on {port}")
            return ser
        except serial.SerialException:
            print(f"[Serial] Could not connect on {port}, retrying in 3s...")
            time.sleep(3)

def wait_for_ready(ser, timeout=30):
    print("[*] Waiting for LoRa board to be ready...")
    start = time.time()
    while True:
        if time.time() - start > timeout:
            raise TimeoutError("[!] Board did not respond within 30s. Check USB connection.")
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line:
            print(f"[Board] {line}")
        if line == "READY":
            print("[*] Board is ready!")
            return

# ─── Packet builders ──────────────────────────────────────────────────────────
def build_hello():
    """HELLO broadcast so neighbours can discover this LoRa node."""
    return json.dumps({
        "type":      "HELLO",
        "node_id":   NODE_ID,
        "protocol":  PROTOCOL_LORA,
        "timestamp": int(time.time() * 1000)
    })

def build_data_packet(packet: Packet):
    return json.dumps({
        "type":         "DATA",
        "src_id":       packet.src_id,
        "dest_id":      packet.dest_id,
        "seq_num":      packet.seq_num,
        "protocol":     packet.protocol,
        "hop_count":    packet.hop_count,
        "path":         packet.path,          # ← added
        "send_time_ms": packet.send_time_ms,
        "rssi":         0
    })

def send_raw(ser, payload: str):
    ser.write(f"SEND:{payload}\n".encode('utf-8'))

# ─── Listener thread ──────────────────────────────────────────────────────────
def handle_incoming(ser):
    """Background thread — listens for incoming LoRa packets via serial."""
    while True:
        try:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if not line:
                continue

            if line.startswith("OK:SENT"):
                print("[*] Packet confirmed sent by board")

            elif line.startswith("RECV:"):
                raw = line[5:]
                try:
                    msg = json.loads(raw)
                    msg_type = msg.get("type", "DATA")

                    if msg_type == "HELLO":
                        neighbor = msg.get("node_id", "UNKNOWN")
                        routing_table.update_route(
                            neighbor_id = neighbor,
                            avg_latency = 0,
                            rssi        = 0,
                            power_cost  = 0.2
                        )
                        print(f"[Hello] Received from {neighbor}")

                    elif msg_type == "DATA":
                        dest = msg.get("dest_id")

                        if dest == NODE_ID:
                            # Packet is for us
                            seq      = msg.get("seq_num", -1)
                            recv     = int(time.time() * 1000)
                            latency  = recv - msg.get("send_time_ms", recv)
                            rssi     = msg.get("rssi", 0)
                            src      = msg.get("src_id", "UNKNOWN")

                            metrics.record_receive(seq, recv)
                            routing_table.update_route(
                                neighbor_id = src,
                                avg_latency = metrics.calculate_average_latency(),
                                rssi        = rssi,
                                power_cost  = 0.2
                            )
                            print(f"[RECV] from={src} seq={seq} latency={latency}ms rssi={rssi}")
                            log_packet({"event": "RECV", "src_id": src, "seq_num": seq,
                                        "rssi": rssi, "latency": latency})

                        elif dest == "GATEWAY":
                            # Not for us — forward to best hop (mesh!)
                            best_hop = routing_table.select_best_next_hop()
                            if best_hop and best_hop != 0xFF:
                                msg["hop_count"] = msg.get("hop_count", 0) + 1
                                msg["path"]      = msg.get("path", []) + [NODE_ID]
                                send_raw(ser, json.dumps(msg))
                                print(f"[Route] Forwarded seq={msg.get('seq_num')} → {best_hop}")
                            else:
                                print("[Route] No neighbours — dropping packet")

                    elif msg_type == "ACK":
                        seq      = msg.get("seq_num", -1)
                        sent     = msg.get("send_time_ms", 0)
                        latency  = int(time.time() * 1000) - sent
                        metrics.record_receive(seq)
                        print(f"[ACK] seq={seq} latency={latency}ms")
                        log_packet({"event": "ACK", "seq_num": seq, "latency": latency})

                except json.JSONDecodeError:
                    print(f"[RECV] Raw (non-JSON): {raw}")

            elif line.startswith("ERROR"):
                print(f"[Board ERROR] {line}")

        except Exception as e:
            print(f"[Listener] Error: {e}")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global seq_num

    port = find_port()
    ser  = connect_serial(port, BAUD_RATE)
    time.sleep(2)

    wait_for_ready(ser)
    print(f"[*] LoRa node '{NODE_ID}' running. Sending every {SEND_INTERVAL}s...\n")

    # Start background listener thread (like wifi_node's _thread.start_new_thread)
    listener = threading.Thread(target=handle_incoming, args=(ser,), daemon=True)
    listener.start()

    last_send    = 0
    last_hello   = 0
    last_summary = 0

    try:
        while True:
            now = time.time()

            # ── Broadcast HELLO every HELLO_INTERVAL ──
            if now - last_hello >= HELLO_INTERVAL:
                send_raw(ser, build_hello())
                print(f"[Hello] Broadcast sent from {NODE_ID}")
                last_hello = now

            # ── Send DATA packet every SEND_INTERVAL ──
            if now - last_send >= SEND_INTERVAL:
                with seq_lock:
                    current_seq = seq_num
                    seq_num = (seq_num + 1) % MAX_SEQ

                pkt = Packet(
                    src_id   = NODE_ID,
                    dest_id  = DEST_ID,
                    seq_num  = current_seq,
                    protocol = PROTOCOL_LORA
                )
                pkt.hop_count = 1
                pkt.path      = [NODE_ID]

                metrics.record_send(current_seq)
                send_raw(ser, build_data_packet(pkt))
                print(f"[SEND] seq={current_seq} t={pkt.send_time_ms}")
                log_packet({"event": "SEND", "seq_num": current_seq,
                            "src_id": NODE_ID, "protocol": PROTOCOL_LORA})
                last_send = now

            # ── Print summary every SUMMARY_INTERVAL ──
            if now - last_summary >= SUMMARY_INTERVAL:
                avg  = metrics.calculate_average_latency()
                best = routing_table.select_best_next_hop()
                print(f"\n── Summary ──────────────────────────")
                print(f"   Packets sent : {seq_num}")
                print(f"   Avg latency  : {avg:.1f} ms")
                print(f"   Best hop     : {best}")
                print(f"─────────────────────────────────────\n")
                last_summary = now

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        ser.close()

if __name__ == "__main__":
    main()