#ifndef AGENT_BANDWIDTH_H
#define AGENT_BANDWIDTH_H

#include <stdint.h>
#include <stddef.h>

// Function to calculate bandwidth usage
double calculate_bandwidth(size_t total_bytes, double total_time_seconds);

#endif // AGENT_BANDWIDTH_H
