import asyncio
import bluetooth
import aioble
import time
import json

from py_nodes.CommonNodeCode.metrics import Metrics
from py_nodes.CommonNodeCode.routing_table import RoutingTable
from py_nodes.CommonNodeCode.packet_format import Packet

_MESH_SERVICE_UUID = bluetooth.UUID(0xFEAA)
_MESH_CHAR_UUID = bluetooth.UUID(0x2A56)


class PicoNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.table = RoutingTable()
        self.metrics = Metrics()
        self.seq_num = 0

    def create_packet(self, dest_id):
        self.seq_num += 1
        pkt = Packet(self.node_id, dest_id, self.seq_num)

        pkt.path = [self.node_id]
        pkt.send_time_ms = int(time.time() * 1000)

        self.metrics.record_send(self.seq_num)

        return pkt


# 🔁 Serialize packet → bytes
def serialize_packet(pkt):
    return json.dumps(pkt.__dict__).encode()


# 🔁 Deserialize bytes → packet
def deserialize_packet(data):
    obj = json.loads(data.decode())

    pkt = Packet(
        obj["src_id"],
        obj["dest_id"],
        obj["seq_num"],
        obj["protocol"]
    )

    pkt.hop_count = obj["hop_count"]
    pkt.path = obj["path"]
    pkt.send_time_ms = obj["send_time_ms"]

    return pkt


# BLE setup
mesh_service = aioble.Service(_MESH_SERVICE_UUID)
mesh_char = aioble.Characteristic(
    mesh_service,
    _MESH_CHAR_UUID,
    write=True,
    read=True,
    notify=True
)

aioble.register_services(mesh_service)


# 📡 Scan neighbors
async def scan_task(node):
    async with aioble.scan(duration_ms=0) as scanner:
        async for result in scanner:
            if result.name() and result.name().startswith("Node_"):
                nid = int(result.name().split("_")[1])
                if nid != node.node_id:
                    node.table.update_route(
                        nid,
                        avg_latency=20,
                        rssi=result.rssi,
                        power_cost=5
                    )


# 📢 Advertise
async def advertise_task(node):
    while True:
        async with aioble.advertise(
            250_000,
            name=f"Node_{node.node_id}",
            services=[_MESH_SERVICE_UUID],
        ):
            await asyncio.sleep(1)


# 📥 Receive + Forward
async def receive_task(node):
    while True:
        conn = await aioble.accept()
        print("Connected!")

        async with conn:
            while True:
                data = await mesh_char.written()

                pkt = deserialize_packet(data)

                node.metrics.record_receive(pkt.seq_num)

                print(f"Received from Node {pkt.src_id}")

                # If reached destination
                if pkt.dest_id == node.node_id:
                    print("Packet reached destination!")
                    continue

                # Forward packet
                pkt.hop_count += 1
                pkt.path.append(node.node_id)

                next_hop = node.table.select_best_next_hop()

                if next_hop != 0xFF:
                    await send_packet(node, next_hop, pkt)


# 📤 Send packet
async def send_packet(node, target_id, pkt):
    target_name = f"Node_{target_id}"

    async with aioble.scan(duration_ms=2000) as scanner:
        async for result in scanner:
            if result.name() == target_name:
                try:
                    conn = await result.connect()

                    async with conn:
                        await mesh_char.write(serialize_packet(pkt))
                        print(f"Sent to Node {target_id}")
                        return
                except Exception as e:
                    print("Send failed:", e)


# 🚀 Main
async def main():
    node = PicoNode(node_id=1)

    asyncio.create_task(scan_task(node))
    asyncio.create_task(advertise_task(node))
    asyncio.create_task(receive_task(node))

    while True:
        await asyncio.sleep(5)

        next_hop = node.table.select_best_next_hop()

        if next_hop != 0xFF:
            pkt = node.create_packet(dest_id=0)  # send to gateway
            await send_packet(node, next_hop, pkt)
        else:
            print("No neighbors yet...")


asyncio.run(main())