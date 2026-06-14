#ifndef AGENT_AGGREGATION_H
#define AGENT_AGGREGATION_H

#include <stdint.h>
#include <stddef.h>

// Function to aggregate multiple small packets into a single larger packet
int aggregate_packets(uint8_t* packets[], size_t packet_sizes[], int num_packets, uint8_t* output_buffer, size_t* output_size);

// Function to deaggregate a single larger packet into multiple small packets
int deaggregate_packets(uint8_t* aggregated_packet, size_t aggregated_size, uint8_t* output_packets[], size_t output_packet_sizes[], int* num_packets);

#endif // AGENT_AGGREGATION_H
