#include "Injector.h"
#include "ProtocolHeaders.h"
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>

extern uint16_t calculateChecksum(uint16_t* addr, int len);

Injector::Injector() : m_handle(nullptr) {}

Injector::~Injector() {
    closeDevice();
}

bool Injector::openDevice(const std::string& interfaceName) {
    m_handle = pcap_open_live(interfaceName.c_str(), 65536, 1, 1000, m_errbuf);
    if (!m_handle) {
        std::cerr << "Injector open failed: " << m_errbuf << std::endl;
        return false;
    }
    return true;
}

void Injector::closeDevice() {
    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}

void Injector::parseMac(const std::string& macStr, uint8_t* mac) {
    unsigned int bytes[6];
    // 支持冒号分隔
    if (sscanf(macStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
        // 简单的错误处理：如果是横杠，这里可能解不对，建议用户统一用冒号
        std::cerr << "MAC format warning: use xx:xx:xx..." << std::endl;
    }
    for(int i=0; i<6; i++) mac[i] = (uint8_t)bytes[i];
}

// TCP 发送
bool Injector::sendTCP(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, const std::string& srcMacStr, const std::string& dstMacStr) {
    if (!m_handle) return false;

    uint8_t packet[sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader)];
    memset(packet, 0, sizeof(packet));

    EthernetHeader* eth = (EthernetHeader*)packet;
    IPHeader* ip = (IPHeader*)(packet + sizeof(EthernetHeader));
    TCPHeader* tcp = (TCPHeader*)(packet + sizeof(EthernetHeader) + sizeof(IPHeader));

    // Ethernet
    parseMac(dstMacStr, eth->dstMac);
    parseMac(srcMacStr, eth->srcMac); // 【关键修改】使用真实的源 MAC
    eth->etherType = htons(0x0800);

    // IP
    ip->ihl = 5;
    ip->version = 4;
    ip->totalLen = htons(sizeof(IPHeader) + sizeof(TCPHeader));
    ip->id = htons(12345);
    ip->ttl = 64;
    ip->protocol = 6;
    ip->srcIP = inet_addr(srcIP.c_str());
    ip->destIP = inet_addr(dstIP.c_str());
    ip->checkSum = calculateChecksum((uint16_t*)ip, sizeof(IPHeader));

    // TCP
    tcp->srcPort = htons(srcPort);
    tcp->destPort = htons(dstPort);
    tcp->seqNum = htonl(1);
    tcp->ackNum = 0;
    tcp->dataOff = 5;
    tcp->flags = 0x02; // SYN
    tcp->window = htons(1024);

    PseudoHeader psh;
    psh.srcIP = ip->srcIP;
    psh.destIP = ip->destIP;
    psh.reserved = 0;
    psh.protocol = 6;
    psh.length = htons(sizeof(TCPHeader));

    std::vector<uint8_t> ckbuf(sizeof(PseudoHeader) + sizeof(TCPHeader));
    memcpy(ckbuf.data(), &psh, sizeof(PseudoHeader));
    memcpy(ckbuf.data() + sizeof(PseudoHeader), tcp, sizeof(TCPHeader));
    tcp->checkSum = calculateChecksum((uint16_t*)ckbuf.data(), ckbuf.size());

    if (pcap_sendpacket(m_handle, packet, sizeof(packet)) != 0) {
        std::cerr << "Error sending packet: " << pcap_geterr(m_handle) << std::endl;
        return false;
    }
    return true;
}

// UDP发送
bool Injector::sendUDP(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, const std::string& msg, const std::string& srcMacStr, const std::string& dstMacStr) {
    if(!m_handle) return false;

    int dataLen = msg.length();
    int totalLen = sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader) + dataLen;
    std::vector<uint8_t> packet(totalLen);

    EthernetHeader* eth = (EthernetHeader*)packet.data();
    IPHeader* ip = (IPHeader*)(packet.data() + sizeof(EthernetHeader));
    UDPHeader* udp = (UDPHeader*)(packet.data() + sizeof(EthernetHeader) + sizeof(IPHeader));
    uint8_t* payload = packet.data() + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader);

    // Ethernet
    parseMac(dstMacStr, eth->dstMac);
    parseMac(srcMacStr, eth->srcMac); // 【关键修改】
    eth->etherType = htons(0x0800);

    // IP
    ip->ihl = 5;
    ip->version = 4;
    ip->totalLen = htons(sizeof(IPHeader) + sizeof(UDPHeader) + dataLen);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->srcIP = inet_addr(srcIP.c_str());
    ip->destIP = inet_addr(dstIP.c_str());
    ip->checkSum = calculateChecksum((uint16_t*)ip, sizeof(IPHeader));

    // UDP
    udp->srcPort = htons(srcPort);
    udp->destPort = htons(dstPort);
    udp->length = htons(sizeof(UDPHeader) + dataLen);
    memcpy(payload, msg.c_str(), dataLen);
    udp->checkSum = 0;

    if (pcap_sendpacket(m_handle, packet.data(), totalLen) != 0) return false;
    return true;
}

// 【修改】ICMP 发送逻辑
bool Injector::sendICMP(const std::string& srcIP, const std::string& dstIP, const std::string& srcMacStr, const std::string& dstMacStr) {
    if(!m_handle) return false;

    int totalLen = sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(ICMPHeader);
    std::vector<uint8_t> packet(totalLen);

    EthernetHeader* eth = (EthernetHeader*)packet.data();
    IPHeader* ip = (IPHeader*)(packet.data() + sizeof(EthernetHeader));
    ICMPHeader* icmp = (ICMPHeader*)(packet.data() + sizeof(EthernetHeader) + sizeof(IPHeader));

    // Ethernet
    parseMac(dstMacStr, eth->dstMac);
    parseMac(srcMacStr, eth->srcMac); // 【关键修改】
    eth->etherType = htons(0x0800);

    // IP
    ip->ihl = 5;
    ip->version = 4;
    ip->totalLen = htons(totalLen - sizeof(EthernetHeader));
    ip->ttl = 64;
    ip->protocol = 1;
    ip->srcIP = inet_addr(srcIP.c_str());
    ip->destIP = inet_addr(dstIP.c_str());
    ip->checkSum = calculateChecksum((uint16_t*)ip, sizeof(IPHeader));

    // ICMP
    icmp->type = 8;
    icmp->code = 0;
    icmp->id = htons(1);
    icmp->sequence = htons(1);
    icmp->checkSum = calculateChecksum((uint16_t*)icmp, sizeof(ICMPHeader));

    if (pcap_sendpacket(m_handle, packet.data(), totalLen) != 0) return false;
    return true;
}