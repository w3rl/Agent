#include "core/sequencing.h"
#include <string.h>

// Forward declaration
static AgentPacket* agent_peer_reassemble(AgentPeer* peer, AgentPacket* fragment);
void cleanup_list(AgentPacket* list);

void agent_peer_init(AgentPeer* peer) {
    if (!peer) return;
    peer->unacknowledgedPackets = NULL;
    peer->incompleteFragments = NULL;
    peer->roundTripTime = AGENT_DEFAULT_RTT;
    peer->nextFragmentID = 0;
    for (int i = 0; i < AGENT_MAX_CHANNELS; ++i) {
        peer->channels[i].incomingSequenceNumber = 0;
        peer->channels[i].outgoingSequenceNumber = 0;
        peer->channels[i].waitingPackets = NULL;
        peer->channels[i].aggregation_queue = NULL;
    }
}

void agent_peer_deinit(AgentPeer* peer) {
    if (!peer) return;
    for (int i = 0; i < AGENT_MAX_CHANNELS; ++i) {
        cleanup_list(peer->channels[i].waitingPackets);
        peer->channels[i].waitingPackets = NULL;
        cleanup_list(peer->channels[i].aggregation_queue);
        peer->channels[i].aggregation_queue = NULL;
    }
    cleanup_list(peer->unacknowledgedPackets);
    peer->unacknowledgedPackets = NULL;
    
    AgentIncompleteFragment* current_frag = peer->incompleteFragments;
    while(current_frag) {
        AgentIncompleteFragment* to_free = current_frag;
        current_frag = current_frag->next;
        cleanup_list(to_free->fragments);
        free(to_free);
    }
    peer->incompleteFragments = NULL;
}

AgentPacket* agent_packet_create(const uint8_t* data, size_t dataLength, AgentPacketFlags flags) {
    AgentPacket* packet = (AgentPacket*)malloc(sizeof(AgentPacket));
    if (!packet) return NULL;
    memset(packet, 0, sizeof(AgentPacket));

    if (dataLength > 0) {
        packet->data = (uint8_t*)malloc(dataLength);
        if (!packet->data) {
            free(packet);
            return NULL;
        }
        memcpy(packet->data, data, dataLength);
    }
    packet->dataLength = dataLength;
    packet->flags = flags;
    return packet;
}

void agent_packet_destroy(AgentPacket* packet) {
    if (!packet) return;
    if (packet->data) {
        free(packet->data);
    }
    free(packet);
}

static int sequence_number_is_newer(uint32_t s1, uint32_t s2) {
    return (s1 > s2 && s1 - s2 <= 2147483648U) || (s1 < s2 && s2 - s1 > 2147483648U);
}

AgentPacket* agent_peer_receive(AgentPeer* peer, AgentPacket* packet, AgentPacket** ackList) {
    if (!peer || !packet) return NULL;
    if (ackList) *ackList = NULL;

    if (packet->flags & AGENT_PACKET_FLAG_ACK) {
        AgentPacket** unacked_ptr = &peer->unacknowledgedPackets;
        while(*unacked_ptr) {
            if ((*unacked_ptr)->channelID == packet->channelID && (*unacked_ptr)->sequenceNumber == packet->acknowledgedSequenceNumber) {
                AgentPacket* acked_packet = *unacked_ptr;
                *unacked_ptr = acked_packet->next;
                agent_packet_destroy(acked_packet);
                break;
            }
            unacked_ptr = &(*unacked_ptr)->next;
        }
        agent_packet_destroy(packet);
        return NULL;
    }

    AgentChannel* channel = &peer->channels[packet->channelID];
    if (packet->sequenceNumber != channel->incomingSequenceNumber && !sequence_number_is_newer(packet->sequenceNumber, channel->incomingSequenceNumber)) {
        agent_packet_destroy(packet);
        return NULL;
    }
    
    if (packet->flags & AGENT_PACKET_FLAG_RELIABLE) {
        AgentPacket* ack = agent_packet_create(NULL, 0, AGENT_PACKET_FLAG_ACK);
        if (ack) {
            ack->channelID = packet->channelID;
            ack->acknowledgedSequenceNumber = packet->sequenceNumber;
            if(ackList) { ack->next = *ackList; *ackList = ack; } else { agent_packet_destroy(ack); }
        }
    }
    
    AgentPacket* ready_list = NULL;
    if (packet->sequenceNumber == channel->incomingSequenceNumber) {
        channel->incomingSequenceNumber++;
        packet->next = NULL;
        ready_list = packet;
        AgentPacket* ready_tail = ready_list;

        int list_changed;
        do {
            list_changed = 0;
            AgentPacket** waiting_ptr = &channel->waitingPackets;
            while (*waiting_ptr) {
                if ((*waiting_ptr)->sequenceNumber == channel->incomingSequenceNumber) {
                    AgentPacket* ready_packet = *waiting_ptr;
                    *waiting_ptr = ready_packet->next;
                    ready_tail->next = ready_packet;
                    ready_tail = ready_packet;
                    ready_tail->next = NULL;
                    channel->incomingSequenceNumber++;
                    list_changed = 1;
                    break;
                } else {
                    waiting_ptr = &(*waiting_ptr)->next;
                }
            }
        } while (list_changed);
    } else if (packet->flags & AGENT_PACKET_FLAG_RELIABLE) {
        AgentPacket** waiting_ptr = &channel->waitingPackets;
        while (*waiting_ptr && sequence_number_is_newer(packet->sequenceNumber, (*waiting_ptr)->sequenceNumber)) {
            waiting_ptr = &(*waiting_ptr)->next;
        }
        packet->next = *waiting_ptr;
        *waiting_ptr = packet;
        return NULL;
    } else {
        agent_packet_destroy(packet);
        return NULL;
    }

    if (!ready_list) return NULL;

    AgentPacket* final_list_head = NULL;
    AgentPacket* final_list_tail = NULL;
    AgentPacket* current_ready = ready_list;
    while (current_ready) {
        AgentPacket* next_in_ready = current_ready->next;
        current_ready->next = NULL;

        AgentPacket* processed_packet = current_ready;
        if (current_ready->flags & AGENT_PACKET_FLAG_FRAGMENT) {
            processed_packet = agent_peer_reassemble(peer, current_ready);
        } else if (current_ready->flags & AGENT_PACKET_FLAG_AGGREGATED) {
            // De-aggregate
            AgentPacket* inner_head = NULL;
            AgentPacket* inner_tail = NULL;
            uint8_t* p = current_ready->data;
            uint8_t* end = current_ready->data + current_ready->dataLength;
            while (p < end) {
                uint16_t inner_size = *(uint16_t*)p;
                p += sizeof(uint16_t);
                AgentPacketFlags inner_flags = *(AgentPacketFlags*)p;
                p += sizeof(AgentPacketFlags);
                AgentPacket* inner_packet = agent_packet_create(p, inner_size, inner_flags);
                p += inner_size;
                if (!inner_head) {
                    inner_head = inner_tail = inner_packet;
                } else {
                    inner_tail->next = inner_packet;
                    inner_tail = inner_packet;
                }
            }
            processed_packet = inner_head;
            agent_packet_destroy(current_ready); // We don't need the container anymore
        }

        if (processed_packet) {
            if (!final_list_head) { final_list_head = processed_packet; } else { final_list_tail->next = processed_packet; }
            AgentPacket* p = processed_packet;
            while(p->next) { p = p->next; }
            final_list_tail = p;
        }
        current_ready = next_in_ready;
    }
    return final_list_head;
}

void agent_peer_update(AgentPeer* peer, uint32_t currentTime, AgentPacket** retransmitList) {
    if (!peer || !retransmitList) return;
    *retransmitList = NULL;
    AgentPacket** unacked_ptr = &peer->unacknowledgedPackets;
    while(*unacked_ptr) {
        if (currentTime > (*unacked_ptr)->sentTime + AGENT_RETRANSMIT_TIMEOUT) {
            AgentPacket* to_retransmit = *unacked_ptr;
            *unacked_ptr = to_retransmit->next;
            to_retransmit->retransmitCount++;
            to_retransmit->sentTime = currentTime;
            to_retransmit->next = *retransmitList;
            *retransmitList = to_retransmit;
        } else {
            unacked_ptr = &(*unacked_ptr)->next;
        }
    }
}

AgentPacket* agent_peer_fragment(AgentPeer* peer, uint8_t channelID, const uint8_t* data, size_t dataLength, AgentPacketFlags flags) {
    if (!peer || !data || dataLength <= AGENT_MTU) return NULL;
    uint16_t fragmentCount = (dataLength + AGENT_MTU - 1) / AGENT_MTU;
    if (fragmentCount > 32) return NULL;

    uint16_t fragmentID = peer->nextFragmentID++;
    AgentPacket* head = NULL;
    AgentPacket* tail = NULL;

    for (uint16_t i = 0; i < fragmentCount; ++i) {
        size_t offset = i * AGENT_MTU;
        size_t length = (i == fragmentCount - 1) ? (dataLength - offset) : AGENT_MTU;

        AgentPacket* frag = agent_packet_create(data + offset, length, flags | AGENT_PACKET_FLAG_FRAGMENT | AGENT_PACKET_FLAG_RELIABLE);
        if (!frag) { cleanup_list(head); return NULL; }
        
        frag->channelID = channelID;
        frag->fragmentID = fragmentID;
        frag->fragmentCount = fragmentCount;
        frag->fragmentNumber = i;
        frag->totalDataLength = dataLength;
        
        if (!head) { head = tail = frag; } else { tail->next = frag; tail = frag; }
    }
    return head;
}

void cleanup_list(AgentPacket* list) {
    AgentPacket* current = list;
    while (current) {
        AgentPacket* to_free = current;
        current = current->next;
        agent_packet_destroy(to_free);
    }
}

static AgentPacket* agent_peer_reassemble(AgentPeer* peer, AgentPacket* fragment) {
    AgentIncompleteFragment** parent_ptr = &peer->incompleteFragments;
    AgentIncompleteFragment* target = NULL;

    while(*parent_ptr) {
        if ((*parent_ptr)->fragmentID == fragment->fragmentID) {
            target = *parent_ptr;
            break;
        }
        parent_ptr = &(*parent_ptr)->next;
    }

    if (!target) {
        target = (AgentIncompleteFragment*)malloc(sizeof(AgentIncompleteFragment));
        if (!target) { agent_packet_destroy(fragment); return NULL; }
        memset(target, 0, sizeof(AgentIncompleteFragment));
        target->fragmentID = fragment->fragmentID;
        target->fragmentCount = fragment->fragmentCount;
        target->totalDataLength = fragment->totalDataLength;
        target->next = peer->incompleteFragments;
        peer->incompleteFragments = target;
        parent_ptr = &peer->incompleteFragments;
    }
    
    AgentPacket** frag_ptr = &target->fragments;
    while (*frag_ptr && (*frag_ptr)->fragmentNumber < fragment->fragmentNumber) { frag_ptr = &(*frag_ptr)->next; }
    fragment->next = *frag_ptr;
    *frag_ptr = fragment;
    
    target->receivedMask |= (1 << fragment->fragmentNumber);

    uint32_t all_received_mask = (1 << target->fragmentCount) - 1;
    if (target->receivedMask != all_received_mask) return NULL;

    uint8_t* full_data = (uint8_t*)malloc(target->totalDataLength);
    if (!full_data) { 
        *parent_ptr = target->next;
        cleanup_list(target->fragments); 
        free(target); 
        return NULL; 
    }

    AgentPacket* current_frag = target->fragments;
    size_t offset = 0;
    while (current_frag) {
        memcpy(full_data + offset, current_frag->data, current_frag->dataLength);
        offset += current_frag->dataLength;
        current_frag = current_frag->next;
    }
    
    AgentPacket* full_packet = agent_packet_create(full_data, target->totalDataLength, (fragment->flags & ~AGENT_PACKET_FLAG_FRAGMENT));
    free(full_data);

    *parent_ptr = target->next;
    cleanup_list(target->fragments);
    free(target);
    
    return full_packet;
}

AgentPacket* agent_peer_send(AgentPeer* peer, uint8_t channelID, const uint8_t* data, size_t dataLength, AgentPacketFlags flags) {
    if (!peer || channelID >= AGENT_MAX_CHANNELS) return NULL;
    AgentChannel* channel = &peer->channels[channelID];
    AgentPacket* packet = agent_packet_create(data, dataLength, flags);
    if (!packet) return NULL;
    packet->channelID = channelID;
    packet->sequenceNumber = channel->outgoingSequenceNumber++;
    return packet;
}

void agent_peer_queue_packet(AgentPeer* peer, uint8_t channelID, AgentPacket* packet) {
    if (!peer || channelID >= AGENT_MAX_CHANNELS || !packet) return;
    AgentChannel* channel = &peer->channels[channelID];
    
    packet->next = NULL;
    if (!channel->aggregation_queue) {
        channel->aggregation_queue = packet;
    } else {
        AgentPacket* tail = channel->aggregation_queue;
        while (tail->next) {
            tail = tail->next;
        }
        tail->next = packet;
    }
}

AgentPacket* agent_peer_create_aggregated_packet(AgentPeer* peer, uint8_t channelID) {
    if (!peer || channelID >= AGENT_MAX_CHANNELS) return NULL;
    AgentChannel* channel = &peer->channels[channelID];
    if (!channel->aggregation_queue) return NULL;

    size_t total_size = 0;
    AgentPacket* current = channel->aggregation_queue;
    while (current) {
        total_size += sizeof(uint16_t) + sizeof(AgentPacketFlags) + current->dataLength;
        current = current->next;
    }

    if (total_size == 0) return NULL;

    uint8_t* aggregated_data = (uint8_t*)malloc(total_size);
    if (!aggregated_data) return NULL;

    uint8_t* p = aggregated_data;
    current = channel->aggregation_queue;
    while (current) {
        *(uint16_t*)p = (uint16_t)current->dataLength;
        p += sizeof(uint16_t);
        *(AgentPacketFlags*)p = current->flags;
        p += sizeof(AgentPacketFlags);
        memcpy(p, current->data, current->dataLength);
        p += current->dataLength;
        current = current->next;
    }
    
    AgentPacket* aggregated_packet = agent_packet_create(aggregated_data, total_size, AGENT_PACKET_FLAG_RELIABLE | AGENT_PACKET_FLAG_AGGREGATED);
    if (aggregated_packet) {
        aggregated_packet->channelID = channelID;
    }
    
    free(aggregated_data);
    cleanup_list(channel->aggregation_queue);
    channel->aggregation_queue = NULL;

    return aggregated_packet;
}
