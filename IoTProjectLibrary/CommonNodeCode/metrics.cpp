#include "metrics.h"

void initMetrics(Metrics *m){
    m->count = 0;
}

void recordSend(Metrics *m, uint16_t seq, uint32_t time){
    if (m->count >= MAX_RECORDS) return;

    m->records[m->count].seq_num = seq;
    m->records[m->count].send_time = time;
    m->records[m->count].recv_time = 0;
    m->records[m->count].latency = 0;

    m->count++;
}

void recordReceive(Metrics *m, uint16_t seq, uint32_t time){
    for (int i = 0; i < m->count; i++){
        if (m->records[i].seq_num == seq){
            m->records[i].recv_time = time;
            m->records[i].latency = time - m->records[i].send_time;

            return;
        }
    }
}

uint16_t calculateAverageLatency(Metrics *m){
    if (m->count == 0) return 0;

    uint32_t total = 0;
    uint16_t valid = 0;

    for (int i = 0; i < m->count; i++){
        if (m->records[i].recv_time != 0){
            total += m->records[i].latency;
            valid++;
        }
    }

    if (valid == 0) return 0;
    return total/ valid;
}