import serial
import serial.tools.list_ports
import time
import json
import sys
import os

# Add CommonNodeCode to path so we can import shared modules (runtime compatibility)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from CommonNodeCode.metrics import Metrics
from CommonNodeCode.packet_format import Packet
from CommonNodeCode.routing_table import RoutingTable

# ─── Config ───────────────────────────────────────────────────────────────────
NODE_ID       = "LORA_A"      # Change per node
DEST_ID       = "GATEWAY"
SEND_INTERVAL = 5             # seconds between test packets
BAUD_RATE     = 9600
# ──────────────────────────────────────────────────────────────────────────────

def find_port():
    """Auto-detect Arduino COM port."""
    ports = serial.tools.list_ports.comports()
    for p in ports:
        if any(kw in p.description for kw in ["Arduino", "CH340", "USB Serial", "ttyUSB", "ttyACM"]):
            print(f"[Auto-detected] {p.device} — {p.description}")
            return p.device
    print("[!] Could not auto-detect port. Available ports:")
    for p in ports:
        print(f"    {p.device} — {p.description}")
    return input("Enter port manually (e.g. COM3 or /dev/ttyUSB0): ").strip()


def wait_for_ready(ser):
    print("[*] Waiting for LoRa board to be ready...")
    while True:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line:
            print(f"[Board] {line}")
        if line == "READY":
            print("[*] Board is ready!")
            return


def send_packet(ser, packet: Packet):
    """Serialise packet to JSON — field names match wifi_node.py and gateway format."""
    payload = json.dumps({
        "type":         "DATA",
        "src_id":       packet.src_id,
        "dest_id":      packet.dest_id,
        "seq_num":      packet.seq_num,
        "protocol":     packet.protocol,
        "hop_count":    packet.hop_count,
        "send_time_ms": packet.send_time_ms,
        "rssi":         0
    })
    ser.write(f"SEND:{payload}\n".encode('utf-8'))


def parse_incoming(line: str, metrics: Metrics, routing_table: RoutingTable):
    """Handle messages coming back from the Arduino."""
    if line.startswith("OK:SENT"):
        print("[*] Packet confirmed sent by board")

    elif line.startswith("RECV:"):
        raw = line[5:]
        try:
            data = json.loads(raw)
            seq  = data.get("seq_num", -1)   # updated from "seq"
            rssi = data.get("rssi", 0)
            src  = data.get("src_id", "UNKNOWN")  # updated from "src"

            # Record receive time for latency calc
            metrics.record_receive(seq)

            avg_lat = metrics.calculate_average_latency()

            # Update routing table — LoRa power cost is low (0.2)
            routing_table.update_route(
                neighbor_id = src,
                avg_latency = avg_lat,
                rssi        = rssi,
                power_cost  = 0.2
            )

            best = routing_table.select_best_next_hop()
            print(f"[RECV] from={src} seq={seq} rssi={rssi} | avg_latency={avg_lat:.1f}ms | best_hop={best}")

        except json.JSONDecodeError:
            print(f"[RECV] Raw (non-JSON): {raw}")

    elif line.startswith("ERROR"):
        print(f"[Board ERROR] {line}")


def main():
    port = find_port()
    ser  = serial.Serial(port, BAUD_RATE, timeout=1)
    time.sleep(2)  # Let Arduino reset

    metrics       = Metrics()
    routing_table = RoutingTable()
    seq           = 0

    wait_for_ready(ser)

    print(f"[*] LoRa node '{NODE_ID}' running. Sending every {SEND_INTERVAL}s...\n")

    last_send = 0

    try:
        while True:
            # ── Send test packet on interval ──
            now = time.time()
            if now - last_send >= SEND_INTERVAL:
                pkt = Packet(
                    src_id   = NODE_ID,
                    dest_id  = DEST_ID,
                    seq_num  = seq,
                    protocol = 3  # 3 = LoRa
                )
                metrics.record_send(seq)
                send_packet(ser, pkt)
                print(f"[SEND] seq={seq} t={pkt.send_time_ms}")
                seq      += 1
                last_send = now

            # ── Read any incoming lines from board ──
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(f"[Board] {line}")
                parse_incoming(line, metrics, routing_table)

    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        ser.close()


if __name__ == "__main__":
    main()