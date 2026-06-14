#include "core/sequencing.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "test.h"

void test_fragmentation_and_reassembly(void) {
    printf("\n--- Testing fragmentation and reassembly ---\n");
    AgentPeer peerA, peerB;
    agent_peer_init(&peerA);
    agent_peer_init(&peerB);

    // 1. Create a large data buffer
    size_t large_size = AGENT_MTU * 2 + 100;
    uint8_t* large_data = (uint8_t*)malloc(large_size);
    for(size_t i = 0; i < large_size; ++i) large_data[i] = i % 256;

    // 2. Fragment the packet
    printf("Fragmenting packet...\n");
    AgentPacket* fragments = agent_peer_fragment(&peerA, 0, large_data, large_size, AGENT_PACKET_FLAG_RELIABLE);
    assert(fragments != NULL);
    AgentPacket* f = fragments;
    int count = 0;
    while(f) { count++; f = f->next; }
    assert(count == 3);
    printf("Packet fragmented into %d packets.\n", count);

    // 3. Simulate receiving fragments in order
    AgentPacket* frag_list = fragments;
    AgentPacket* final_packet = NULL;
    int frag_num = 0;
    while(frag_list) {
        printf("Receiving fragment %d...\n", frag_num++);
        AgentPacket* current_frag = frag_list;
        frag_list = frag_list->next;
        current_frag->next = NULL;
        current_frag->sequenceNumber = peerB.channels[0].outgoingSequenceNumber++;

        AgentPacket* reassembled = agent_peer_receive(&peerB, current_frag, NULL);
        if (reassembled) {
            printf("Packet reassembled.\n");
            assert(final_packet == NULL); // Should only get one final packet
            final_packet = reassembled;
        }
    }

    // 4. Verify the final packet
    printf("Verifying final packet...\n");
    assert(final_packet != NULL);
    assert(!(final_packet->flags & AGENT_PACKET_FLAG_FRAGMENT));
    assert(final_packet->dataLength == large_size);
    assert(memcmp(final_packet->data, large_data, large_size) == 0);

    printf("Cleaning up...\n");

    cleanup_list(final_packet);
    free(large_data);
    agent_peer_deinit(&peerA);
    agent_peer_deinit(&peerB);
    printf("...PASSED\n");
}

void test_out_of_order_reassembly(void) {
    printf("\n--- Testing out-of-order reassembly ---\n");
    AgentPeer peerA, peerB;
    agent_peer_init(&peerA);
    agent_peer_init(&peerB);

    size_t large_size = AGENT_MTU + 100;
    uint8_t* large_data = (uint8_t*)malloc(large_size);
    for(size_t i = 0; i < large_size; ++i) large_data[i] = (i+10) % 256;

    printf("Fragmenting packet...\n");
    AgentPacket* fragments = agent_peer_fragment(&peerA, 0, large_data, large_size, AGENT_PACKET_FLAG_RELIABLE);
    assert(fragments != NULL && fragments->next != NULL);
    
    // Manually shuffle: send fragment 1, then 0
    AgentPacket* frag0 = fragments;
    AgentPacket* frag1 = fragments->next;
    frag0->next = NULL;
    frag1->next = NULL;

    frag1->sequenceNumber = peerB.channels[0].outgoingSequenceNumber++;
    frag0->sequenceNumber = peerB.channels[0].outgoingSequenceNumber++;

    printf("Receiving fragment 1 (out of order)...\n");
    peerB.channels[0].incomingSequenceNumber = frag1->sequenceNumber; // hack to bypass sequencing
    AgentPacket* reassembled = agent_peer_receive(&peerB, frag1, NULL);
    assert(reassembled == NULL); // Should be stalled in reassembly

    printf("Receiving fragment 0...\n");
    peerB.channels[0].incomingSequenceNumber = frag0->sequenceNumber; // hack
    reassembled = agent_peer_receive(&peerB, frag0, NULL);
    assert(reassembled != NULL); // Now it should complete
    printf("Packet reassembled.\n");

    printf("Verifying final packet...\n");
    assert(reassembled->dataLength == large_size);
    assert(memcmp(reassembled->data, large_data, large_size) == 0);
    
    printf("Cleaning up...\n");
    cleanup_list(reassembled);
    free(large_data);
    agent_peer_deinit(&peerA);
    agent_peer_deinit(&peerB);
    printf("...PASSED\n");
}

int main(void) {
    test_fragmentation_and_reassembly();
    test_out_of_order_reassembly();
    printf("\nAll Fragmentation tests passed!\n");
    return 0;
}
