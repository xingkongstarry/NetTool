#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <pcap.h>

// 回调：传递长度和原始数据
using PacketCallback = std::function<void(const struct pcap_pkthdr*, const u_char*)>;

class Sniffer {
public:
    Sniffer();
    ~Sniffer();

    // 获取所有可用网卡列表
    static std::vector<std::pair<std::string, std::string>> getAllDevices();

    // 初始化指定网卡
    bool openDevice(const std::string& interfaceName);

    // 设置过滤器
    bool setFilter(const std::string& filterExp);

    // 开始抓包
    void startCapture(PacketCallback callback);

    // 停止抓包
    void stopCapture();

private:
    pcap_t* m_handle;
    char m_errbuf[PCAP_ERRBUF_SIZE]{};
    std::atomic<bool> m_running;
    struct bpf_program m_fp{};
};

#endif // SNIFFER_H