import asyncio
import bluetooth
import aioble
import json

from py_nodes.CommonNodeCode.metrics import Metrics
from py_nodes.CommonNodeCode.packet_format import Packet

_MESH_SERVICE_UUID = bluetooth.UUID(0xFEAA)
_MESH_CHAR_UUID = bluetooth.UUID(0x2A56)

metrics = Metrics()


# 🔁 Deserialize
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


async def gateway():
    print("Gateway started...")

    while True:
        conn = await aioble.accept()

        async with conn:
            while True:
                data = await mesh_char.written()

                pkt = deserialize_packet(data)

                metrics.record_receive(pkt.seq_num)

                avg_latency = metrics.calculate_average_latency()

                print("\n=== Packet Received ===")
                print(f"From Node: {pkt.src_id}")
                print(f"Hop Count: {pkt.hop_count}")
                print(f"Path: {pkt.path}")
                print(f"Average Latency: {avg_latency:.2f} ms")


asyncio.run(gateway())