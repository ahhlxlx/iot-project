import time

class MetricRecord:
    def __init__(self, seq_num, send_time):
        self.seq_num = seq_num
        self.send_time = send_time
        self.recv_time = 0
        self.latency = 0

class Metrics:
    MAX_RECORDS = 50

    def __init__(self):
        self.records = []

    def record_send(self, seq, timestamp=None):
        if len(self.records) >= self.MAX_RECORDS:
            self.records.pop(0)
        
        t = timestamp if timestamp is not None else int(time.time() * 1000)
        self.records.append(MetricRecord(seq,t))

    def record_receive(self, seq, timestamp=None):
        t = timestamp if timestamp is not None else int(time.time() * 1000)
        for record in self.records:
            if record.seq_num == seq:
                record.recv_time = t
                record.latency = record.recv_time - record.send_time
                break

    def calculate_average_latency(self):
        valid_records = [r.latency for r in self.records if r.recv_time != 0]
        if not valid_records:
            return 0
        return sum(valid_records) / len(valid_records)