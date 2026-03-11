#include <ArduinoBLE.h>

#include <packet_format.h>
#include <routing_table.h>
#include <metrics.h>

#define NODE_ID 1
#define PROTOCOL_BLE 1
#define PACKET_SIZE sizeof(Packet)

RoutingTable routingTable;
Metrics metrics;

uint16_t seq_counter = 0;
unsigned long lastSend = 0;

/* BLE Service + Characteristic */
BLEService meshService("180A");
BLECharacteristic packetChar("2A57", BLERead | BLEWrite | BLENotify, PACKET_SIZE);

/* Create Packet */
Packet createPacket(uint8_t dest) {

    Packet pkt;

    pkt.src_id = NODE_ID;
    pkt.dest_id = dest;
    pkt.hop_count = 0;
    pkt.seq_num = seq_counter++;
    pkt.protocol = PROTOCOL_BLE;
    pkt.send_time_ms = millis();

    pkt.path[0] = NODE_ID;

    return pkt;
}

/* Send BLE Packet */
void sendBLEPacket(Packet *pkt) {

    recordSend(&metrics, pkt->seq_num, pkt->send_time_ms);

    packetChar.writeValue((byte*)pkt, PACKET_SIZE);

    Serial.print("Sent packet seq=");
    Serial.println(pkt->seq_num);
}

/* Handle Received Packet */
void handleReceivedPacket(Packet *pkt, int8_t rssi) {

    uint32_t recv_time = millis();

    recordReceive(&metrics, pkt->seq_num, recv_time);

    uint16_t latency = recv_time - pkt->send_time_ms;

    updateRoute(&routingTable, pkt->src_id, latency, rssi, 1);

    Serial.print("Received packet from node ");
    Serial.println(pkt->src_id);

    if (pkt->dest_id != NODE_ID) {
        forwardPacket(pkt);
    }
}

/* Forward Packet */
void forwardPacket(Packet *pkt) {

    if (pkt->hop_count >= MAX_HOPS)
        return;

    pkt->hop_count++;

    uint8_t nextHop = selectBestNextHop(&routingTable);

    if (nextHop != 0xFF) {
        sendBLEPacket(pkt);
    }
}

/* BLE Setup */
void initBLE() {

    if (!BLE.begin()) {
        Serial.println("BLE start failed");
        while (1);
    }

    BLE.setLocalName("MeshNode");
    BLE.setAdvertisedService(meshService);

    meshService.addCharacteristic(packetChar);
    BLE.addService(meshService);

    packetChar.writeValue((uint8_t)0);

    BLE.advertise();

    Serial.println("BLE Mesh Node Started");
}

/* Setup */
void setup() {

    Serial.begin(115200);

    initRoutingTable(&routingTable);
    initMetrics(&metrics);

    initBLE();
}

/* Loop */
void loop() {

    BLEDevice central = BLE.central();

    if (central) {

        Serial.print("Connected to: ");
        Serial.println(central.address());

        while (central.connected()) {

            if (packetChar.written()) {

                Packet pkt;

                packetChar.readValue((byte*)&pkt, PACKET_SIZE);

                int8_t rssi = central.rssi();

                handleReceivedPacket(&pkt, rssi);
            }

            /* Send test packet every 3 seconds */
            if (millis() - lastSend > 3000) {

                Packet pkt = createPacket(0); // broadcast

                sendBLEPacket(&pkt);

                lastSend = millis();
            }
        }

        Serial.println("Disconnected");
    }
}