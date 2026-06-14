#include "core/sequencing.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

// Helper to create a packet for testing
AgentPacket* create_test_packet(uint32_t seq, uint8_t channel, AgentPacketFlags flags, const char* data) {
    AgentPacket* p = agent_packet_create((const uint8_t*)data, data ? strlen(data) + 1 : 0, flags);
    assert(p != NULL);
    p->sequenceNumber = seq;
    p->channelID = channel;
    return p;
}

#include "test.h"

void test_in_order_delivery(void) {
    printf("Testing in-order delivery...");
    AgentPeer peer;
    agent_peer_init(&peer);

    AgentPacket* p0 = create_test_packet(0, 0, AGENT_PACKET_FLAG_RELIABLE, "p0");
    AgentPacket* p1 = create_test_packet(1, 0, AGENT_PACKET_FLAG_RELIABLE, "p1");

    AgentPacket* ready_list = agent_peer_receive(&peer, p0, NULL);
    assert(ready_list != NULL);
    assert(ready_list->sequenceNumber == 0);
    assert(ready_list->next == NULL);
    assert(peer.channels[0].incomingSequenceNumber == 1);
    cleanup_list(ready_list);

    ready_list = agent_peer_receive(&peer, p1, NULL);
    assert(ready_list != NULL);
    assert(ready_list->sequenceNumber == 1);
    assert(ready_list->next == NULL);
    assert(peer.channels[0].incomingSequenceNumber == 2);
    cleanup_list(ready_list);

    agent_peer_deinit(&peer);
    printf("...PASSED");
}

void test_old_packet_discard(void) {
    printf("Testing old packet discard...");
    AgentPeer peer;
    agent_peer_init(&peer);

    AgentPacket* p0 = create_test_packet(0, 0, AGENT_PACKET_FLAG_RELIABLE, "p0");
    AgentPacket* p0_dup = create_test_packet(0, 0, AGENT_PACKET_FLAG_RELIABLE, "p0_dup");

    AgentPacket* ready_list = agent_peer_receive(&peer, p0, NULL);
    assert(ready_list != NULL);
    cleanup_list(ready_list);

    ready_list = agent_peer_receive(&peer, p0_dup, NULL);
    assert(ready_list == NULL); // Duplicate should be discarded
    assert(peer.channels[0].incomingSequenceNumber == 1);

    agent_peer_deinit(&peer);
    printf("...PASSED");
}

void test_unreliable_out_of_order_discard(void) {
    printf("Testing unreliable out-of-order discard...");
    AgentPeer peer;
    agent_peer_init(&peer);

    AgentPacket* p1 = create_test_packet(1, 0, AGENT_PACKET_FLAG_NONE, "p1");
    AgentPacket* ready_list = agent_peer_receive(&peer, p1, NULL);
    assert(ready_list == NULL); // p1 is newer, but unreliable, should be discarded
    assert(peer.channels[0].incomingSequenceNumber == 0);
    assert(peer.channels[0].waitingPackets == NULL);

    agent_peer_deinit(&peer);
    printf("...PASSED");
}

void test_reliable_out_of_order_stall_and_process(void) {
    printf("Testing reliable out-of-order stall and process...");
    AgentPeer peer;
    agent_peer_init(&peer);

    AgentPacket* p1 = create_test_packet(1, 0, AGENT_PACKET_FLAG_RELIABLE, "p1");
    AgentPacket* p0 = create_test_packet(0, 0, AGENT_PACKET_FLAG_RELIABLE, "p0");

    // Receive p1 (out of order), should be stalled
    AgentPacket* ready_list = agent_peer_receive(&peer, p1, NULL);
    assert(ready_list == NULL);
    assert(peer.channels[0].incomingSequenceNumber == 0);
    assert(peer.channels[0].waitingPackets != NULL);
    assert(peer.channels[0].waitingPackets->sequenceNumber == 1);

    // Receive p0 (the missing packet)
    ready_list = agent_peer_receive(&peer, p0, NULL);
    assert(ready_list != NULL);

    // Should get both p0 and p1 back, in order
    assert(ready_list->sequenceNumber == 0);
    assert(ready_list->next != NULL);
    assert(ready_list->next->sequenceNumber == 1);
    assert(ready_list->next->next == NULL);

    assert(peer.channels[0].incomingSequenceNumber == 2);
    assert(peer.channels[0].waitingPackets == NULL);

    cleanup_list(ready_list);
    agent_peer_deinit(&peer);
    printf("...PASSED");
}

void test_multiple_stalled_packets(void) {
    printf("Testing multiple stalled packets...");
    AgentPeer peer;
    agent_peer_init(&peer);

    AgentPacket* p3 = create_test_packet(3, 1, AGENT_PACKET_FLAG_RELIABLE, "p3");
    AgentPacket* p1 = create_test_packet(1, 1, AGENT_PACKET_FLAG_RELIABLE, "p1");
    AgentPacket* p2 = create_test_packet(2, 1, AGENT_PACKET_FLAG_RELIABLE, "p2");
    AgentPacket* p0 = create_test_packet(0, 1, AGENT_PACKET_FLAG_RELIABLE, "p0");

    // Send 3, 1, 2 out of order
    assert(agent_peer_receive(&peer, p3, NULL) == NULL);
    assert(agent_peer_receive(&peer, p1, NULL) == NULL);
    assert(agent_peer_receive(&peer, p2, NULL) == NULL);

    assert(peer.channels[1].incomingSequenceNumber == 0);
    // waiting list should be sorted: 1, 2, 3
    assert(peer.channels[1].waitingPackets != NULL);
    assert(peer.channels[1].waitingPackets->sequenceNumber == 1);
    assert(peer.channels[1].waitingPackets->next->sequenceNumber == 2);
    assert(peer.channels[1].waitingPackets->next->next->sequenceNumber == 3);

    // Send p0, should release the whole queue
    AgentPacket* ready_list = agent_peer_receive(&peer, p0, NULL);
    assert(ready_list != NULL);
    
    // Check if we got 0, 1, 2, 3
    assert(ready_list->sequenceNumber == 0);
    assert(ready_list->next->sequenceNumber == 1);
    assert(ready_list->next->next->sequenceNumber == 2);
    assert(ready_list->next->next->next->sequenceNumber == 3);
    assert(ready_list->next->next->next->next == NULL);

    assert(peer.channels[1].incomingSequenceNumber == 4);
    assert(peer.channels[1].waitingPackets == NULL);

    cleanup_list(ready_list);
    agent_peer_deinit(&peer);
    printf("...PASSED");
}


int main(void) {
    test_in_order_delivery();
    test_old_packet_discard();
    test_unreliable_out_of_order_discard();
    test_reliable_out_of_order_stall_and_process();
    test_multiple_stalled_packets();

    printf("All sequencing tests passed!");

    return 0;
}
