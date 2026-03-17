"""
gateway/gateway_receiver.py
Listens for incoming packets from all node types (WiFi/UDP, LoRa/Serial)
and forwards the processed data to the backend server via HTTP POST.

                ┌──────────────┐
  WiFi nodes ──▶│              │  HTTP POST /api/packets
  LoRa nodes ──▶│   Gateway    │─────────────────────────▶ Backend (server.py)
  BLE  nodes ──▶│  Receiver    │
                └──────────────┘

The gateway is the FINAL DESTINATION for mesh packets (dest_id = "GATEWAY").
It does NOT forward packets further — that is the mesh's job.
"""

import socket
import json
import time
import logging
import threading
import requests
from dotenv import load_dotenv
load_dotenv()
# ─── Config ───────────────────────────────────────────────────────────────────
BACKEND_URL    = "http://localhost:5000/api/packets"   # adjust if backend is remote
UDP_PORT       = 5005          # must match wifi_node.py UDP_PORT
BUFFER_SIZE    = 1024
POST_TIMEOUT   = 3             # seconds before giving up on a backend POST
MAX_RETRIES    = 3
RETRY_DELAY    = 0.5           # seconds between retries

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GW-RECV] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ─── Backend forwarding ───────────────────────────────────────────────────────

def forward_to_backend(packet_dict: dict, retries: int = MAX_RETRIES):
    """
    POST a normalised packet dict to the backend server.
    Retries up to MAX_RETRIES times on transient failures.
    """
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                BACKEND_URL,
                json=packet_dict,
                timeout=POST_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 201:
                log.info("▶ FWD  src=%-12s seq=%05d  [%d ms]",
                         packet_dict.get("src_id"),
                         packet_dict.get("seq_num", -1),
                         resp.json().get("latency_ms", 0))
                return True
            else:
                log.warning("Backend returned %d: %s", resp.status_code, resp.text[:120])
        except requests.exceptions.ConnectionError:
            log.warning("Backend unreachable (attempt %d/%d)", attempt, retries)
        except requests.exceptions.Timeout:
            log.warning("Backend timeout (attempt %d/%d)", attempt, retries)
        except Exception as e:
            log.error("Unexpected error forwarding packet: %s", e)

        if attempt < retries:
            time.sleep(RETRY_DELAY)

    log.error("Failed to forward packet after %d attempts — dropping", retries)
    return False


def normalise_packet(raw: dict, received_at_ms: float = None) -> dict:
    """
    Ensure every field the backend expects is present.
    Fills safe defaults for any optional field the node omitted.
    """
    if received_at_ms is None:
        received_at_ms = time.time() * 1000

    return {
        "src_id":       raw.get("src_id",       "UNKNOWN"),
        "dest_id":      raw.get("dest_id",       "GATEWAY"),
        "seq_num":      raw.get("seq_num",       0),
        "protocol":     raw.get("protocol",      2),      # default WiFi
        "hop_count":    raw.get("hop_count",     0),
        "path":         raw.get("path",          []),
        "send_time_ms": raw.get("send_time_ms",  int(received_at_ms)),
        "rssi":         raw.get("rssi",          0),
        "received_at":  received_at_ms,
    }


# ─── WiFi / UDP listener ──────────────────────────────────────────────────────

def udp_listener():
    """
    Binds a UDP socket on UDP_PORT.
    Accepts DATA packets from WiFi nodes (and any other UDP senders).
    Discards HELLO packets — those are peer-discovery only.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    log.info("UDP listener bound on port %d", UDP_PORT)

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            received_at = time.time() * 1000

            try:
                msg = json.loads(data.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                log.warning("Non-JSON UDP packet from %s — ignored", addr[0])
                continue

            msg_type = msg.get("type", "DATA")

            if msg_type == "HELLO":
                # Hello messages are for peer discovery — not forwarded
                log.debug("HELLO from %s — ignored", msg.get("node_id", addr[0]))
                continue

            if msg_type == "DATA":
                dest = msg.get("dest_id")
                if dest not in ("GATEWAY", 0xFF):
                    # Not addressed to gateway — should not arrive here
                    log.debug("Packet dest=%s not for gateway — ignored", dest)
                    continue

                pkt = normalise_packet(msg, received_at)
                log.info("◀ RECV UDP  src=%-12s seq=%05d proto=%d hops=%d  from=%s",
                         pkt["src_id"], pkt["seq_num"],
                         pkt["protocol"], pkt["hop_count"], addr[0])

                threading.Thread(
                    target=forward_to_backend,
                    args=(pkt,),
                    daemon=True,
                ).start()

        except OSError as e:
            log.error("UDP socket error: %s", e)
        except Exception as e:
            log.error("UDP listener error: %s", e)


# ─── LoRa / Serial listener ───────────────────────────────────────────────────

def serial_listener(port: str, baud: int = 9600):
    """
    Reads JSON lines from a serial port connected to the LoRa Arduino.
    Lines prefixed with "RECV:" are parsed as LoRa packets.
    Runs in its own thread.
    """
    try:
        import serial
    except ImportError:
        log.warning("pyserial not installed — LoRa serial listener disabled")
        return

    while True:
        try:
            ser = serial.Serial(port, baud, timeout=1)
            log.info("Serial listener connected on %s @ %d baud", port, baud)

            while True:
                line = ser.readline().decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                received_at = time.time() * 1000

                if line.startswith("RECV:"):
                    raw = line[5:]
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        log.warning("Non-JSON LoRa line: %s", raw[:80])
                        continue

                    if msg.get("type") == "DATA" and msg.get("dest_id") in ("GATEWAY", 0xFF):
                        pkt = normalise_packet(msg, received_at)
                        pkt["protocol"] = 3    # force LoRa protocol code

                        log.info("◀ RECV LORA src=%-12s seq=%05d hops=%d",
                                 pkt["src_id"], pkt["seq_num"], pkt["hop_count"])

                        threading.Thread(
                            target=forward_to_backend,
                            args=(pkt,),
                            daemon=True,
                        ).start()

        except Exception as e:
            log.error("Serial listener error on %s: %s — reconnecting in 5s", port, e)
            time.sleep(5)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    import sys
    log.info("Gateway receiver starting …")

    # UDP thread (WiFi + BLE-over-UDP nodes)
    t_udp = threading.Thread(target=udp_listener, daemon=True)
    t_udp.start()

    # Serial thread — only if a LoRa port is configured
    lora_port = None
    if len(sys.argv) > 1:
        lora_port = sys.argv[1]
    elif __import__("os").environ.get("LORA_PORT"):
        lora_port = __import__("os").environ["LORA_PORT"]

    if lora_port:
        t_serial = threading.Thread(
            target=serial_listener, args=(lora_port,), daemon=True
        )
        t_serial.start()
        log.info("LoRa serial listener started on %s", lora_port)
    else:
        log.info("No LORA_PORT specified — serial listener not started")
        log.info("  Start with:  python gateway_receiver.py COM3")
        log.info("  or set env:  LORA_PORT=/dev/ttyUSB0")

    log.info("Gateway receiver running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()