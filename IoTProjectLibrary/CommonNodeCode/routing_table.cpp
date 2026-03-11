#include "routing_table.h"

void initRoutingTable(RoutingTable *table) {
    table->count = 0;
}

void updateRoute(RoutingTable *table, uint8_t neighbor, uint16_t latency, int8_t rssi, uint8_t power_cost) {
    for (int i = 0; i < table->count; i++) {
        if (table->entries[i].neighbor_id == neighbor) {
            table->entries[i].avg_latency = latency;
            table->entries[i].rssi = rssi;
            table->entries[i].power_cost = power_cost;
            return;
        }
    }

    if (table->count < MAX_NEIGHBORS) {
        table->entries[table->count].neighbor_id = neighbor;
        table->entries[table->count].avg_latency = latency;
        table->entries[table->count].rssi = rssi;
        table->entries[table->count].power_cost = power_cost;
        table->count++;
    }
}

uint8_t selectBestNextHop(RoutingTable *table) {
    uint16_t bestCost = 65535;
    uint8_t bestNeighbor = 0xFF;

    for (int i = 0; i < table->count; i++) {
        uint16_t cost = table->entries[i].avg_latency +
                        (table->entries[i].power_cost * 10);

        if (cost < bestCost) {
            bestCost = cost;
            bestNeighbor = table->entries[i].neighbor_id;
        }
    }
    return bestNeighbor;
}