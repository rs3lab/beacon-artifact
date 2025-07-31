#pragma once
#include <stdlib.h>
#include <cstdint>

inline int16_t randNum16() {
    int16_t num = rand();
    return num % 2 == 1 ? num : num - RAND_MAX;
}

inline uint16_t urandNum16() {
    uint16_t num = rand();
    return num;
}

inline int32_t randNum32() {
    int32_t num = rand();
    return num % 2 == 1 ? num : num - RAND_MAX;
}

inline uint32_t urandNum32() {
    uint32_t num = rand();
    return num;
}

inline int64_t randNum64() {
    int64_t num = rand();
    return num % 2 == 1 ? num : num - RAND_MAX;
}

inline uint64_t urandNum64() {
    uint64_t num = rand();
    return num;
}

inline int64_t randRange(int begin, int end) {
    return begin + int64_t(rand() % (end-begin+1));
}
