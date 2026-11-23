#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/resource.h>

static unsigned int process_data(unsigned int value) {
    volatile unsigned char buffer[64];

    buffer[0] = (unsigned char)value;
    buffer[63] = (unsigned char)(value >> 8);

    return (unsigned int)buffer[0]
         + (unsigned int)buffer[63];
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iterations>\n", argv[0]);
        return 1;
    }

    char *end;
    unsigned long long iterations =
        strtoull(argv[1], &end, 10);

    if (*end != '\0' || iterations == 0) {
        fprintf(stderr, "Invalid iteration count\n");
        return 1;
    }

    struct timespec start, finish;
    struct rusage usage;
    uint64_t checksum = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned long long i = 0; i < iterations; i++) {
        checksum += process_data((unsigned int)i);
    }

    clock_gettime(CLOCK_MONOTONIC, &finish);

    getrusage(RUSAGE_SELF, &usage);

    double seconds =
        (finish.tv_sec - start.tv_sec) +
        (finish.tv_nsec - start.tv_nsec) / 1e9;

    printf("RUNTIME_SECONDS=%.9f\n", seconds);
    printf("MAX_RSS_KB=%ld\n", usage.ru_maxrss);
    printf("CHECKSUM=%llu\n",
           (unsigned long long)checksum);

    return 0;
}
