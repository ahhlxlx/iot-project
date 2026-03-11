// Purpose of this file is to check if user has uploaded IoTProjectLibrary.zip and can run CommonNodeCode Library properly
#include <packet_format.h>
#include <routing_table.h>
#include <metrics.h>

Metrics metrics;
RoutingTable routing;

void setup() {

  Serial.begin(115200);
  while (!Serial);

  Serial.println("=== IoT Mesh Library Test ===");
  Serial.print("Library Version: ");
  Serial.println(LIB_VERSION);

  // Test Metrics
  initMetrics(&metrics);

  recordSend(&metrics, 1, 100);
  recordReceive(&metrics, 1, 150);

  uint16_t avgLatency = calculateAverageLatency(&metrics);

  Serial.print("Average latency: ");
  Serial.println(avgLatency);

  // Test Routing Table
  initRoutingTable(&routing);

  updateRoute(&routing, 2, 20, -50, 1);
  updateRoute(&routing, 3, 40, -60, 2);

  uint8_t best = selectBestNextHop(&routing);

  Serial.print("Best next hop: ");
  Serial.println(best);

  // Test Packet Structure
  Packet pkt;

  pkt.src_id = 1;
  pkt.dest_id = 2;
  pkt.seq_num = 10;
  pkt.hop_count = 0;
  pkt.protocol = 1;

  Serial.println("Packet structure created successfully");

}

void loop() {
}