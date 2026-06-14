#include "core/sequencing.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

// Helper to clone a packet, since the original might be modified or freed.
AgentPacket* clone_packet(AgentPacket* p) {
    if (!p) return NULL;
    AgentPacket* clone = agent_packet_create(p->data, p->dataLength, p->flags);
    assert(clone != NULL);
    clone->sequenceNumber = p->sequenceNumber;
    clone->acknowledgedSequenceNumber = p->acknowledgedSequenceNumber;
    clone->channelID = p->channelID;
    clone->sentTime = p->sentTime;
    clone->retransmitCount = p->retransmitCount;
    return clone;
}

#include "test.h"


void test_ack_process(void) {
    printf("Testing ACK processing...");
    AgentPeer peerA, peerB;
    agent_peer_init(&peerA);
    agent_peer_init(&peerB);

    // 1. Peer A sends a reliable packet
    AgentPacket* p0_sent = agent_peer_send(&peerA, 0, (uint8_t*)"hello", 6, AGENT_PACKET_FLAG_RELIABLE);
    p0_sent->sentTime = 1000; // Mock send time

    // 2. Simulate sending by adding a clone to unacknowledged list
    AgentPacket* p0_unacked_clone = clone_packet(p0_sent);
    p0_unacked_clone->next = peerA.unacknowledgedPackets;
    peerA.unacknowledgedPackets = p0_unacked_clone;
    
    assert(peerA.unacknowledgedPackets != NULL);
    assert(peerA.unacknowledgedPackets->sequenceNumber == 0);

    // 3. Peer B receives it.
    AgentPacket* ack_list = NULL;
    AgentPacket* ready_list = agent_peer_receive(&peerB, p0_sent, &ack_list);
    
    assert(ready_list != NULL);
    assert(ready_list->sequenceNumber == 0);
    assert(strcmp((char*)ready_list->data, "hello") == 0);
    cleanup_list(ready_list);
    
    assert(ack_list != NULL);
    assert(ack_list->flags & AGENT_PACKET_FLAG_ACK);
    assert(ack_list->acknowledgedSequenceNumber == 0);
    assert(ack_list->next == NULL);

    // 4. Peer A receives the ACK
    ready_list = agent_peer_receive(&peerA, ack_list, NULL);
    assert(ready_list == NULL);

    // 5. Verify packet is removed from unacknowledged list
    assert(peerA.unacknowledgedPackets == NULL);

    agent_peer_deinit(&peerA);
    agent_peer_deinit(&peerB);
    printf("...PASSED");
}


void test_retransmission(void) {
    printf("Testing Retransmission...");
    AgentPeer peerA;
    agent_peer_init(&peerA);

    // 1. Peer A sends a reliable packet
    AgentPacket* p0 = agent_peer_send(&peerA, 0, (uint8_t*)"lost", 5, AGENT_PACKET_FLAG_RELIABLE);
    p0->sentTime = 2000; // Mock send time
    p0->next = peerA.unacknowledgedPackets;
    peerA.unacknowledgedPackets = p0;

    // 2. Time passes, packet is considered lost. Call update.
    uint32_t now = 2000 + AGENT_RETRANSMIT_TIMEOUT + 1;
    AgentPacket* retransmit_list = NULL;
    agent_peer_update(&peerA, now, &retransmit_list);

    // 3. Verify packet is in the retransmit list
    assert(retransmit_list != NULL);
    assert(retransmit_list->sequenceNumber == 0);
    assert(retransmit_list->retransmitCount == 1);
    assert(retransmit_list->sentTime == now);
    assert(retransmit_list->next == NULL);
    
    // 4. The original packet is now gone from the unacknowledged list
    assert(peerA.unacknowledgedPackets == NULL);

    cleanup_list(retransmit_list);

    agent_peer_deinit(&peerA);
    printf("...PASSED");
}


int main(void) {
    test_ack_process();
    test_retransmission();
    printf("All ACK/Retransmission tests passed!");
    return 0;
}
