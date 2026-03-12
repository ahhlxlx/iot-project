import time


class Packet:
    # Protocol 1 = BLE, 2 = WiFi, 3 = LoRa
    def __init__(self, src_id, dest_id, seq_num, protocol = 1):
        self.src_id = src_id
        self.dest_id = dest_id
        self.seq_num = seq_num
        self.protocol = protocol

        self.hop_count = 0
        self.path = []
        self.send_time_ms = int(time.time() * 1000)
        self.rssi = 0
        