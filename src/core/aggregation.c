#include "core/aggregation.h"
#include <string.h>

int aggregate_packets(uint8_t* packets[], size_t packet_sizes[], int num_packets, uint8_t* output_buffer, size_t* output_size) {
    size_t current_offset = 0;
    for (int i = 0; i < num_packets; ++i) {
        // Store the size of the packet first (using a simple size_t prefix)
        memcpy(output_buffer + current_offset, &packet_sizes[i], sizeof(size_t));
        current_offset += sizeof(size_t);

        // Copy the packet data
        memcpy(output_buffer + current_offset, packets[i], packet_sizes[i]);
        current_offset += packet_sizes[i];
    }
    *output_size = current_offset;
    return 0; // Success
}

int deaggregate_packets(uint8_t* aggregated_packet, size_t aggregated_size, uint8_t* output_packets[], size_t output_packet_sizes[], int* num_packets) {
    size_t current_offset = 0;
    int packet_count = 0;
    while (current_offset < aggregated_size) {
        // Read the size of the next packet
        size_t packet_size;
        memcpy(&packet_size, aggregated_packet + current_offset, sizeof(size_t));
        current_offset += sizeof(size_t);

        // Store the size and a pointer to the packet data
        output_packet_sizes[packet_count] = packet_size;
        output_packets[packet_count] = aggregated_packet + current_offset;
        current_offset += packet_size;
        packet_count++;
    }
    *num_packets = packet_count;
    return 0; // Success
}
