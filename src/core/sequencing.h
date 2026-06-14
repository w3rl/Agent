#ifndef AGENT_SEQUENCING_H
#define AGENT_SEQUENCING_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define AGENT_MAX_CHANNELS 32
#define AGENT_DEFAULT_RTT 200 // Default Round Trip Time in ms
#define AGENT_RETRANSMIT_TIMEOUT 500 // Initial retransmit timeout
#define AGENT_MTU 1400 // Maximum Transmission Unit

// Forward declarations
typedef struct _AgentPeer AgentPeer;
typedef struct _AgentPacket AgentPacket;
typedef struct _AgentIncompleteFragment AgentIncompleteFragment;

typedef enum {
    AGENT_PACKET_FLAG_NONE = 0,
    AGENT_PACKET_FLAG_RELIABLE = 1 << 0,
    AGENT_PACKET_FLAG_ACK = 1 << 1,
    AGENT_PACKET_FLAG_FRAGMENT = 1 << 2, // This packet is a fragment of a larger one
    AGENT_PACKET_FLAG_AGGREGATED = 1 << 3, // This packet contains multiple smaller packets
} AgentPacketFlags;

struct _AgentPacket {
    uint32_t sequenceNumber;
    uint32_t acknowledgedSequenceNumber;
    uint8_t channelID;
    AgentPacketFlags flags;

    // Fragmentation fields
    uint16_t fragmentID;
    uint16_t fragmentCount;
    uint16_t fragmentNumber;
    uint32_t totalDataLength;

    size_t dataLength;
    uint8_t* data;

    // For queueing
    AgentPacket* next;

    // For retransmission
    uint32_t sentTime;
    uint8_t retransmitCount;
};

struct _AgentIncompleteFragment {
    uint16_t fragmentID;
    uint16_t fragmentCount;
    uint32_t totalDataLength;
    uint32_t receivedMask; // Using a bitmask for up to 32 fragments.
    AgentPacket* fragments; // Linked list of received fragment packets
    AgentIncompleteFragment* next;
};

typedef struct {
    uint32_t incomingSequenceNumber;
    uint32_t outgoingSequenceNumber;
    AgentPacket* waitingPackets;
    AgentPacket* aggregation_queue;
} AgentChannel;

struct _AgentPeer {
    AgentChannel channels[AGENT_MAX_CHANNELS];
    AgentPacket* unacknowledgedPackets;
    AgentIncompleteFragment* incompleteFragments;
    uint32_t roundTripTime;
    uint16_t nextFragmentID;
};

// Core functions
void agent_peer_init(AgentPeer* peer);
void agent_peer_deinit(AgentPeer* peer);
AgentPacket* agent_packet_create(const uint8_t* data, size_t dataLength, AgentPacketFlags flags);
void agent_packet_destroy(AgentPacket* packet);
AgentPacket* agent_peer_receive(AgentPeer* peer, AgentPacket* packet, AgentPacket** ackList);
void agent_peer_update(AgentPeer* peer, uint32_t currentTime, AgentPacket** retransmitList);

// Fragmentation functions
AgentPacket* agent_peer_fragment(AgentPeer* peer, uint8_t channelID, const uint8_t* data, size_t dataLength, AgentPacketFlags flags);

// Aggregation functions
void agent_peer_queue_packet(AgentPeer* peer, uint8_t channelID, AgentPacket* packet);
AgentPacket* agent_peer_create_aggregated_packet(AgentPeer* peer, uint8_t channelID);

// Sending function
AgentPacket* agent_peer_send(AgentPeer* peer, uint8_t channelID, const uint8_t* data, size_t dataLength, AgentPacketFlags flags);



#endif // AGENT_SEQUENCING_H
