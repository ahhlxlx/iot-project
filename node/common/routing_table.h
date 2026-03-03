#ifndef ROUTING_TABLE_H
#define ROUTING_TABLE_H

#include <stdint.h>

#define MAX_NEIGHBORS 10

typedef struct {
    uint8_t neighbor_id;
    uint16_t avg_latency;
    int8_t rssi;
    uint8_t power_cost;
} RouteEntry;

typedef struct {
    RouteEntry entries[MAX_NEIGHBORS];
    uint8_t count;
} RoutingTable;

void initRoutingTable(RoutingTable *table);
void updateRoute(RoutingTable *table, uint8_t neighbor, uint16_t latency, int8_t rssi, uint8_t power_cost);
uint8_t selectBestNextHop(RoutingTable *table);

#endif