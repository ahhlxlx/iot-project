import network
import socket
import time
import random

# Node information
NODE_ID = "WIFI_NODE_1"
PROTOCOL = "WIFI"

# WiFi credentials
SSID = "lixuan"
PASSWORD = "testTest"

# Gateway information
GATEWAY_IP = "172.20.10.4"   # Raspberry Pi gateway IP
GATEWAY_PORT = 5005

sequence_number = 0

def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(SSID, PASSWORD)
    print("Connecting to WiFi...")
    while not wlan.isconnected():
        time.sleep(1)
    print("Connected!")
    print("IP Address:", wlan.ifconfig()[0])

def generate_packet():
    global sequence_number
    sequence_number += 1
    timestamp = int(time.time())
    hop_count = 1
    rssi = random.randint(-70, -40)
    packet = f"{NODE_ID},{PROTOCOL},{timestamp},{hop_count},{rssi},{sequence_number}"
    return packet

def main():
    connect_wifi()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:

        packet = generate_packet()

        print("Sending packet:", packet)

        sock.sendto(packet.encode(), (GATEWAY_IP, GATEWAY_PORT))

        time.sleep(5)

main()