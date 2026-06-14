#include <stdio.h>
#include <assert.h>
#include "core/bandwidth.h"

void test_bandwidth(void) {
    printf("Testing bandwidth...\n");

    double bandwidth = calculate_bandwidth(1024, 2.0);
    assert(bandwidth == 512.0);

    bandwidth = calculate_bandwidth(0, 5.0);
    assert(bandwidth == 0.0);

    bandwidth = calculate_bandwidth(1024, 0.0);
    assert(bandwidth == 0.0);

    bandwidth = calculate_bandwidth(1024, -1.0);
    assert(bandwidth == 0.0);

    printf("Bandwidth test passed.\n");
}

int main(void) {
    test_bandwidth();
    return 0;
}
