#include "ProtocolHeaders.h"

uint16_t calculateChecksum(uint16_t* addr, int len) {
    long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len > 0) {
        sum += *reinterpret_cast<uint8_t*>(addr);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}