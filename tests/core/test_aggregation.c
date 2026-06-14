#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "core/aggregation.h"

void test_aggregation(void) {
    printf("Testing aggregation...\n");

    uint8_t p1[] = {0x01, 0x02, 0x03};
    uint8_t p2[] = {0x04, 0x05, 0x06, 0x07};
    uint8_t p3[] = {0x08, 0x09};

    uint8_t* packets[] = {p1, p2, p3};
    size_t packet_sizes[] = {sizeof(p1), sizeof(p2), sizeof(p3)};
    int num_packets = 3;

    uint8_t output_buffer[100];
    size_t output_size = 0;

    int result = aggregate_packets(packets, packet_sizes, num_packets, output_buffer, &output_size);
    assert(result == 0);
    assert(output_size > 0);

    uint8_t* deaggregated_packets_ptr[10];
    size_t deaggregated_packet_sizes[10];
    int deaggregated_num_packets = 0;

    result = deaggregate_packets(output_buffer, output_size, deaggregated_packets_ptr, deaggregated_packet_sizes, &deaggregated_num_packets);
    assert(result == 0);
    assert(deaggregated_num_packets == num_packets);

    for (int i = 0; i < num_packets; ++i) {
        assert(packet_sizes[i] == deaggregated_packet_sizes[i]);
        assert(memcmp(packets[i], deaggregated_packets_ptr[i], packet_sizes[i]) == 0);
    }

    printf("Aggregation test passed.\n");
}

int main(void) {
    test_aggregation();
    return 0;
}
