#include "Sniffer.h"
#include <iostream>

// 增加一个全局变量或成员变量来存储错误信息是不够线程安全的，
// 但为了简化你的改动，我们利用 errbuf
// (注意：请确保 Sniffer.h 里面没有修改，还是原来的定义)

Sniffer::Sniffer() : m_handle(nullptr), m_running(false) {
    m_errbuf[0] = '\0';
}

Sniffer::~Sniffer() {
    stopCapture();
    if (m_handle) {
        pcap_close(m_handle);
    }
}

std::vector<std::pair<std::string, std::string>> Sniffer::getAllDevices() {
    std::vector<std::pair<std::string, std::string>> devices;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return devices;
    }

    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::string name = d->name ? d->name : "";
        std::string desc = d->description ? d->description : "";
        devices.push_back({name, desc});
    }

    pcap_freealldevs(alldevs);
    return devices;
}

bool Sniffer::openDevice(const std::string& interfaceName) {
    // 【重要修改】将超时时间从 1 改为 1000 ms，防止疯狂空转
    m_handle = pcap_open_live(interfaceName.c_str(), 65536, 1, 1000, m_errbuf);
    if (m_handle == nullptr) {
        std::cerr << "Cannot open device: " << m_errbuf << std::endl;
        return false;
    }
    return true;
}

bool Sniffer::setFilter(const std::string& filterExp) {
    if (!m_handle) return false;
    if (filterExp.empty()) return true; // 如果过滤器为空，直接返回成功

    uint32_t netmask = 0xffffff00;

    if (pcap_compile(m_handle, &m_fp, filterExp.c_str(), 0, netmask) == -1) {
        std::cerr << "Bad filter: " << pcap_geterr(m_handle) << std::endl;
        // 将错误信息复制到 m_errbuf 方便上层获取
        snprintf(m_errbuf, PCAP_ERRBUF_SIZE, "Filter Error: %s", pcap_geterr(m_handle));
        return false;
    }
    if (pcap_setfilter(m_handle, &m_fp) == -1) {
        snprintf(m_errbuf, PCAP_ERRBUF_SIZE, "SetFilter Error: %s", pcap_geterr(m_handle));
        return false;
    }
    return true;
}

void Sniffer::startCapture(PacketCallback callback) {
    if (!m_handle) return;
    m_running = true;

    while (m_running) {
        struct pcap_pkthdr* header;
        const u_char* pkt_data;

        // 使用 pcap_next_ex
        int res = pcap_next_ex(m_handle, &header, &pkt_data);

        if (res == 1) { // 捕获到数据包
            callback(header, pkt_data);
        } else if (res == 0) {
            // 超时，继续循环
            continue;
        } else if (res == -1 || res == -2) {
            // 出错或文件结束，退出
            // 这里可以加一个打印
            std::cerr << "pcap_next_ex stopped: " << res << std::endl;
            break;
        }
    }
}

void Sniffer::stopCapture() {
    m_running = false;
}