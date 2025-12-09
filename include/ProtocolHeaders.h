#pragma once
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#pragma pack(push, 1)

// Ethernet Header (14 bytes)
struct EthernetHeader {
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t etherType;
};

// ARP Header (28 bytes)
struct ARPHeader {
    uint16_t hardwareType; // 硬件类型 (Ethernet=1)
    uint16_t protocolType; // 协议类型 (IPv4=0x0800)
    uint8_t  hwAddrLen;    // 硬件地址长度 (6)
    uint8_t  protoAddrLen; // 协议地址长度 (4)
    uint16_t opcode;       // 操作码 (1=Request, 2=Reply)
    uint8_t  senderMac[6]; // 发送方 MAC
    uint32_t senderIP;     // 发送方 IP
    uint8_t  targetMac[6]; // 目标 MAC
    uint32_t targetIP;     // 目标 IP
};

// IP Header
struct IPHeader {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t totalLen;
    uint16_t id;
    uint16_t fragOff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checkSum;
    uint32_t srcIP;
    uint32_t destIP;
};

// TCP Header
struct TCPHeader {
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  reserved : 4;
    uint8_t  dataOff : 4;
    uint8_t  flags;
    uint16_t window;
    uint16_t checkSum;
    uint16_t urgPtr;
};

// UDP Header
struct UDPHeader {
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checkSum;
};

// ICMP Header
struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checkSum;
    uint16_t id;
    uint16_t sequence;
};

// Pseudo Header
struct PseudoHeader {
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t length;
};

#pragma pack(pop)