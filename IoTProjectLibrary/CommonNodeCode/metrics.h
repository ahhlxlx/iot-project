#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

#define MAX_RECORDS 50

typedef struct {
    uint16_t seq_num;
    uint32_t send_time;
    uint32_t recv_time;
    uint16_t latency;
} MetricRecord;

typedef struct {
    MetricRecord records[MAX_RECORDS];
    uint8_t count;
} Metrics;

void initMetrics(Metrics *m);
void recordSend(Metrics *m, uint16_t seq, uint32_t time);
void recordReceive(Metrics *m, uint16_t seq, uint32_t time);
uint16_t calculateAverageLatency(Metrics *m);

#endif