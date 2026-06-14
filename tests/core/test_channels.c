#include "core/sequencing.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

// Helper from test_acks.c, might need to be moved to a common test header later
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

void test_independent_sequencing(void) {
    printf("Testing independent channel sequencing...");
    AgentPeer peer;
    agent_peer_init(&peer);

    // Send packet 0 on channel 0
    AgentPacket* p_ch0_0 = agent_peer_send(&peer, 0, (uint8_t*)"ch0_0", 6, AGENT_PACKET_FLAG_RELIABLE);
    // Send packet 0 on channel 1
    AgentPacket* p_ch1_0 = agent_peer_send(&peer, 1, (uint8_t*)"ch1_0", 6, AGENT_PACKET_FLAG_RELIABLE);

    assert(p_ch0_0->sequenceNumber == 0);
    assert(p_ch1_0->sequenceNumber == 0);
    assert(peer.channels[0].outgoingSequenceNumber == 1);
    assert(peer.channels[1].outgoingSequenceNumber == 1);

    AgentPacket* ready_list = agent_peer_receive(&peer, p_ch0_0, NULL);
    assert(ready_list != NULL && ready_list->channelID == 0);
    assert(peer.channels[0].incomingSequenceNumber == 1);
    assert(peer.channels[1].incomingSequenceNumber == 0);
    cleanup_list(ready_list);

    ready_list = agent_peer_receive(&peer, p_ch1_0, NULL);
    assert(ready_list != NULL && ready_list->channelID == 1);
    assert(peer.channels[0].incomingSequenceNumber == 1);
    assert(peer.channels[1].incomingSequenceNumber == 1);
    cleanup_list(ready_list);
    
    agent_peer_deinit(&peer);
    printf("...PASSED");
}

void test_independent_stalling_and_acks(void) {
    printf("Testing independent stalling and ACKs...");
    AgentPeer peerA, peerB;
    agent_peer_init(&peerA);
    agent_peer_init(&peerB);

    // Manually create packet 1 for channel 0 to force out-of-order receipt
    AgentPacket* p_ch0_1 = agent_packet_create((uint8_t*)"ch0_1", 6, AGENT_PACKET_FLAG_RELIABLE);
    p_ch0_1->channelID = 0;
    p_ch0_1->sequenceNumber = 1;

    // Use agent_peer_send for the in-order packet on channel 1
    AgentPacket* p_ch1_0 = agent_peer_send(&peerA, 1, (uint8_t*)"ch1_0", 6, AGENT_PACKET_FLAG_RELIABLE);
    assert(p_ch1_0->sequenceNumber == 0);
    
    // Peer B receives out-of-order packet for ch0, it should be stalled.
    AgentPacket* ack_list = NULL;
    AgentPacket* ready_list = agent_peer_receive(&peerB, p_ch0_1, &ack_list);
    assert(ready_list == NULL); // Check that it was stalled
    assert(ack_list != NULL); // Should still generate an ACK for the received packet
    assert(peerB.channels[0].waitingPackets != NULL);
    assert(peerB.channels[0].waitingPackets->sequenceNumber == 1);
    assert(peerB.channels[1].waitingPackets == NULL);
    cleanup_list(ack_list);
    ack_list = NULL;

    // Peer B receives in-order packet for ch1, it should be processed.
    ready_list = agent_peer_receive(&peerB, p_ch1_0, &ack_list);
    assert(ready_list != NULL);
    assert(ready_list->channelID == 1);
    assert(peerB.channels[0].waitingPackets != NULL); // ch0 still waiting
    assert(peerB.channels[1].incomingSequenceNumber == 1);
    assert(ack_list != NULL);
    assert(ack_list->channelID == 1);
    cleanup_list(ready_list);
    cleanup_list(ack_list);

    agent_peer_deinit(&peerA);
    agent_peer_deinit(&peerB);
    printf("...PASSED");
}

int main(void) {
    test_independent_sequencing();
    test_independent_stalling_and_acks();
    printf("All channel tests passed!");
    return 0;
}
