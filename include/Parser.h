#ifndef PARSER_H
#define PARSER_H

#include "ProtocolHeaders.h"
#include <string>
#include <vector>
#include <pcap.h>
#include <QTreeWidget>
#include <QString>

class PacketParser {
public:
    struct ParsedInfo {
        std::string srcMac, dstMac;
        std::string srcIP, dstIP;
        std::string protocol;
        std::string info;
        int length;
    };

    static ParsedInfo parse(const struct pcap_pkthdr* pkthdr, const u_char* packet);

    // 生成详细树
    static void analyzeToTree(const std::vector<uint8_t>& data, QTreeWidget* tree);

private:
    static std::string macToString(const uint8_t* mac);

    // 【修改】统一为一个添加函数，不再区分 name/value 两列
    static void addTreeItem(QTreeWidgetItem* parent, QString text, int offset, int len);
};

#endif // PARSER_H