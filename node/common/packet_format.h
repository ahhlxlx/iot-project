#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H

#include <stdint.h>

#define MAX_HOPS 10

typedef struct {
    uint8_t src_id;
    uint8_t dest_id;
    uint8_t hop_count;
    uint8_t path[MAX_HOPS];
    uint32_t send_time_ms;
    uint16_t seq_num;
    uint8_t protocol; // 0=WiFi, 1=BLE, 2=LoRa
} Packet;

#endif