#include "core/bandwidth.h"

double calculate_bandwidth(size_t total_bytes, double total_time_seconds) {
    if (total_time_seconds <= 0) {
        return 0.0;
    }
    return (double)total_bytes / total_time_seconds;
}
