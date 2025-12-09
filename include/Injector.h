#ifndef INJECTOR_H
#define INJECTOR_H

#include <string>
#include <pcap.h>

class Injector {
public:
    Injector();
    ~Injector();

    bool openDevice(const std::string& interfaceName);
    void closeDevice();

    // 【修改】所有函数都增加了 srcMac 参数
    bool sendTCP(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, const std::string& srcMac, const std::string& dstMac);
    bool sendUDP(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort, const std::string& msg, const std::string& srcMac, const std::string& dstMac);
    bool sendICMP(const std::string& srcIP, const std::string& dstIP, const std::string& srcMac, const std::string& dstMac);

private:
    pcap_t* m_handle;
    char m_errbuf[PCAP_ERRBUF_SIZE];

    void parseMac(const std::string& macStr, uint8_t* mac);
};

#endif