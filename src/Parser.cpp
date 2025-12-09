#include "Parser.h"
#include <sstream>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// --- 辅助函数 ---
std::string PacketParser::macToString(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(int i=0; i<6; ++i) {
        ss << std::setw(2) << (int)mac[i];
        if(i!=5) ss << ":";
    }
    return ss.str();
}

void PacketParser::addTreeItem(QTreeWidgetItem* parent, QString text, int offset, int len) {
    QTreeWidgetItem* item = new QTreeWidgetItem(parent);
    item->setText(0, text);
    item->setData(0, Qt::UserRole, offset);
    item->setData(1, Qt::UserRole, len);
}

// --- 简略解析 (列表显示) ---
PacketParser::ParsedInfo PacketParser::parse(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    ParsedInfo info;
    info.length = pkthdr->len;
    info.protocol = "Unknown";

    if (info.length < sizeof(EthernetHeader)) {
        info.info = "[Malformed]";
        return info;
    }

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);
    info.srcMac = macToString(eth->srcMac);
    info.dstMac = macToString(eth->dstMac);
    uint16_t type = ntohs(eth->etherType);

    if (type == 0x0800) { // IPv4
        const IPHeader* ip = reinterpret_cast<const IPHeader*>(packet + sizeof(EthernetHeader));
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        struct in_addr s, d; s.s_addr = ip->srcIP; d.s_addr = ip->destIP;
        inet_ntop(AF_INET, &s, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &d, dst, INET_ADDRSTRLEN);
        info.srcIP = src; info.dstIP = dst;

        size_t ipLen = ip->ihl * 4;
        const u_char* trans = packet + sizeof(EthernetHeader) + ipLen;

        if (ip->protocol == 6) {
            info.protocol = "TCP";
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(trans);
            std::stringstream ss;
            ss << ntohs(tcp->srcPort) << " -> " << ntohs(tcp->destPort);
            if (tcp->flags & 0x02) ss << " [SYN]";
            if (tcp->flags & 0x10) ss << " [ACK]";
            if (tcp->flags & 0x01) ss << " [FIN]";
            if (tcp->flags & 0x04) ss << " [RST]";
            info.info = ss.str();
            if (ntohs(tcp->destPort) == 80 || ntohs(tcp->srcPort) == 80) info.protocol = "HTTP";
        } else if (ip->protocol == 17) {
            info.protocol = "UDP";
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(trans);
            std::stringstream ss;
            ss << ntohs(udp->srcPort) << " -> " << ntohs(udp->destPort);
            info.info = ss.str();
        } else if (ip->protocol == 1) {
            info.protocol = "ICMP";
            const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(trans);
            info.info = (icmp->type == 8) ? "Echo Request" : ((icmp->type == 0) ? "Echo Reply" : "ICMP");
        } else {
            info.protocol = "IP";
        }
    } else if (type == 0x0806) { // 【修改】ARP 解析逻辑
        info.protocol = "ARP";
        if (info.length >= sizeof(EthernetHeader) + sizeof(ARPHeader)) {
            const ARPHeader* arp = reinterpret_cast<const ARPHeader*>(packet + sizeof(EthernetHeader));
            uint16_t op = ntohs(arp->opcode);
            char targetIp[INET_ADDRSTRLEN];
            struct in_addr tip; tip.s_addr = arp->targetIP;
            inet_ntop(AF_INET, &tip, targetIp, INET_ADDRSTRLEN);

            if (op == 1) info.info = "Who has " + std::string(targetIp) + "? Tell " + macToString(arp->senderMac);
            else if (op == 2) info.info = std::string(targetIp) + " is at " + macToString(arp->senderMac);
            else info.info = "Unknown ARP Opcode";

            // ARP 的 srcIP/dstIP 不在 IP 头里，需要手动提取
            char senderIp[INET_ADDRSTRLEN];
            struct in_addr sip; sip.s_addr = arp->senderIP;
            inet_ntop(AF_INET, &sip, senderIp, INET_ADDRSTRLEN);
            info.srcIP = senderIp;
            info.dstIP = targetIp;
        } else {
            info.info = "[Short ARP]";
        }
    }
    return info;
}

// --- 详细树构建 ---
void PacketParser::analyzeToTree(const std::vector<uint8_t>& data, QTreeWidget* tree) {
    tree->clear();
    const u_char* packet = data.data();
    int totalLen = data.size();

    if (totalLen < sizeof(EthernetHeader)) return;

    // 1. Frame
    QTreeWidgetItem* itemFrame = new QTreeWidgetItem(tree);
    itemFrame->setText(0, QString("Frame 1: %1 bytes on wire (%2 bits)").arg(totalLen).arg(totalLen * 8));
    itemFrame->setData(0, Qt::UserRole, 0);
    itemFrame->setData(1, Qt::UserRole, totalLen);

    // 2. Ethernet II
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);
    QTreeWidgetItem* itemEth = new QTreeWidgetItem(tree);
    itemEth->setText(0, QString("Ethernet II, Src: %1, Dst: %2")
            .arg(QString::fromStdString(macToString(eth->srcMac)))
            .arg(QString::fromStdString(macToString(eth->dstMac))));
    itemEth->setData(0, Qt::UserRole, 0);
    itemEth->setData(1, Qt::UserRole, 14);

    addTreeItem(itemEth, QString("Destination: %1").arg(QString::fromStdString(macToString(eth->dstMac))), 0, 6);
    addTreeItem(itemEth, QString("Source: %1").arg(QString::fromStdString(macToString(eth->srcMac))), 6, 6);
    // 判断下一层协议类型
    uint16_t ethType = ntohs(eth->etherType);
    QString typeStr = "Unknown";
    if (ethType == 0x0800) typeStr = "IPv4";
    else if (ethType == 0x0806) typeStr = "ARP";

    addTreeItem(itemEth, QString("Type: %1 (0x%2)").arg(typeStr).arg(ethType, 4, 16, QChar('0')), 12, 2);

    // --- 3. ARP 解析 (新增) ---
    if (ethType == 0x0806) {
        if (totalLen < 14 + sizeof(ARPHeader)) return;
        const ARPHeader* arp = reinterpret_cast<const ARPHeader*>(packet + 14);
        int arpOffset = 14;

        QTreeWidgetItem* itemArp = new QTreeWidgetItem(tree);
        itemArp->setText(0, QString("Address Resolution Protocol (%1)").arg(ntohs(arp->opcode) == 1 ? "request" : "reply"));
        itemArp->setData(0, Qt::UserRole, arpOffset);
        itemArp->setData(1, Qt::UserRole, sizeof(ARPHeader));

        addTreeItem(itemArp, QString("Hardware type: Ethernet (%1)").arg(ntohs(arp->hardwareType)), arpOffset, 2);
        addTreeItem(itemArp, QString("Protocol type: IPv4 (0x%1)").arg(ntohs(arp->protocolType), 4, 16, QChar('0')), arpOffset+2, 2);
        addTreeItem(itemArp, QString("Hardware size: %1").arg(arp->hwAddrLen), arpOffset+4, 1);
        addTreeItem(itemArp, QString("Protocol size: %1").arg(arp->protoAddrLen), arpOffset+5, 1);
        addTreeItem(itemArp, QString("Opcode: %1 (%2)").arg(ntohs(arp->opcode) == 1 ? "request" : "reply").arg(ntohs(arp->opcode)), arpOffset+6, 2);

        addTreeItem(itemArp, QString("Sender MAC address: %1").arg(QString::fromStdString(macToString(arp->senderMac))), arpOffset+8, 6);

        char senderIp[INET_ADDRSTRLEN];
        struct in_addr sip; sip.s_addr = arp->senderIP;
        inet_ntop(AF_INET, &sip, senderIp, INET_ADDRSTRLEN);
        addTreeItem(itemArp, QString("Sender IP address: %1").arg(senderIp), arpOffset+14, 4);

        addTreeItem(itemArp, QString("Target MAC address: %1").arg(QString::fromStdString(macToString(arp->targetMac))), arpOffset+18, 6);

        char targetIp[INET_ADDRSTRLEN];
        struct in_addr tip; tip.s_addr = arp->targetIP;
        inet_ntop(AF_INET, &tip, targetIp, INET_ADDRSTRLEN);
        addTreeItem(itemArp, QString("Target IP address: %1").arg(targetIp), arpOffset+24, 4);

        return; // ARP 解析结束
    }

    if (ethType != 0x0800 || totalLen < 34) return;

    // --- 3. IPv4 解析 (保持不变) ---
    const IPHeader* ip = reinterpret_cast<const IPHeader*>(packet + 14);
    int ipHeaderLen = ip->ihl * 4;

    QTreeWidgetItem* itemIp = new QTreeWidgetItem(tree);
    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
    struct in_addr s, d; s.s_addr = ip->srcIP; d.s_addr = ip->destIP;
    inet_ntop(AF_INET, &s, srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &d, dstIp, INET_ADDRSTRLEN);

    itemIp->setText(0, QString("Internet Protocol Version 4, Src: %1, Dst: %2").arg(srcIp).arg(dstIp));
    itemIp->setData(0, Qt::UserRole, 14);
    itemIp->setData(1, Qt::UserRole, ipHeaderLen);

    addTreeItem(itemIp, QString("Version: %1").arg(ip->version), 14, 1);
    addTreeItem(itemIp, QString("Header Length: %1 bytes (%2)").arg(ipHeaderLen).arg(ip->ihl), 14, 1);
    addTreeItem(itemIp, QString("Total Length: %1 (0x%2)").arg(ntohs(ip->totalLen)).arg(ntohs(ip->totalLen), 4, 16, QChar('0')), 16, 2);
    addTreeItem(itemIp, QString("Identification: 0x%1 (%2)").arg(ntohs(ip->id), 4, 16, QChar('0')).arg(ntohs(ip->id)), 18, 2);
    addTreeItem(itemIp, QString("Time to Live: %1").arg(ip->ttl), 22, 1);
    addTreeItem(itemIp, QString("Protocol: %1 (%2)").arg(ip->protocol == 6 ? "TCP" : (ip->protocol == 17 ? "UDP" : (ip->protocol == 1 ? "ICMP" : "Unknown"))).arg(ip->protocol), 23, 1);
    addTreeItem(itemIp, QString("Header Checksum: 0x%1").arg(ntohs(ip->checkSum), 4, 16, QChar('0')), 24, 2);
    addTreeItem(itemIp, QString("Source Address: %1").arg(srcIp), 26, 4);
    addTreeItem(itemIp, QString("Destination Address: %1").arg(dstIp), 30, 4);

    int transOffset = 14 + ipHeaderLen;
    int remaining = totalLen - transOffset;
    const u_char* trans = packet + transOffset;

    // 4. Transport Layer
    if (ip->protocol == 6 && remaining >= sizeof(TCPHeader)) { // TCP
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(trans);
        int tcpHeaderLen = tcp->dataOff * 4;

        QTreeWidgetItem* itemTcp = new QTreeWidgetItem(tree);
        itemTcp->setText(0, QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2").arg(ntohs(tcp->srcPort)).arg(ntohs(tcp->destPort)));
        itemTcp->setData(0, Qt::UserRole, transOffset);
        itemTcp->setData(1, Qt::UserRole, tcpHeaderLen);

        addTreeItem(itemTcp, QString("Source Port: %1 (0x%2)").arg(ntohs(tcp->srcPort)).arg(ntohs(tcp->srcPort), 4, 16, QChar('0')), transOffset, 2);
        addTreeItem(itemTcp, QString("Destination Port: %1 (0x%2)").arg(ntohs(tcp->destPort)).arg(ntohs(tcp->destPort), 4, 16, QChar('0')), transOffset+2, 2);
        addTreeItem(itemTcp, QString("Sequence Number: %1 (0x%2)").arg(ntohl(tcp->seqNum)).arg(ntohl(tcp->seqNum), 8, 16, QChar('0')), transOffset+4, 4);
        addTreeItem(itemTcp, QString("Acknowledgment Number: %1 (0x%2)").arg(ntohl(tcp->ackNum)).arg(ntohl(tcp->ackNum), 8, 16, QChar('0')), transOffset+8, 4);
        addTreeItem(itemTcp, QString("Header Length: %1 bytes").arg(tcpHeaderLen), transOffset+12, 1);

        // Flags
        QTreeWidgetItem* flagsItem = new QTreeWidgetItem(itemTcp);
        flagsItem->setText(0, QString("Flags: 0x%1").arg(tcp->flags, 3, 16, QChar('0')));
        flagsItem->setData(0, Qt::UserRole, transOffset+13);
        flagsItem->setData(1, Qt::UserRole, 1);

        addTreeItem(flagsItem, QString("Urgent: %1").arg((tcp->flags & 0x20) ? "Set" : "Not Set"), transOffset+13, 1);
        addTreeItem(flagsItem, QString("Acknowledgment: %1").arg((tcp->flags & 0x10) ? "Set" : "Not Set"), transOffset+13, 1);
        addTreeItem(flagsItem, QString("Push: %1").arg((tcp->flags & 0x08) ? "Set" : "Not Set"), transOffset+13, 1);
        addTreeItem(flagsItem, QString("Reset: %1").arg((tcp->flags & 0x04) ? "Set" : "Not Set"), transOffset+13, 1);
        addTreeItem(flagsItem, QString("Syn: %1").arg((tcp->flags & 0x02) ? "Set" : "Not Set"), transOffset+13, 1);
        addTreeItem(flagsItem, QString("Fin: %1").arg((tcp->flags & 0x01) ? "Set" : "Not Set"), transOffset+13, 1);

        addTreeItem(itemTcp, QString("Window: %1").arg(ntohs(tcp->window)), transOffset+14, 2);
        addTreeItem(itemTcp, QString("Checksum: 0x%1").arg(ntohs(tcp->checkSum), 4, 16, QChar('0')), transOffset+16, 2);

        // HTTP
        int payloadOffset = transOffset + tcpHeaderLen;
        int payloadLen = totalLen - payloadOffset;
        if (payloadLen > 0) {
            if (ntohs(tcp->srcPort) == 80 || ntohs(tcp->destPort) == 80) {
                QTreeWidgetItem* itemHttp = new QTreeWidgetItem(tree);
                itemHttp->setText(0, "Hypertext Transfer Protocol");
                itemHttp->setData(0, Qt::UserRole, payloadOffset);
                itemHttp->setData(1, Qt::UserRole, payloadLen);
                std::string s((const char*)(packet+payloadOffset), std::min(payloadLen, 64));
                addTreeItem(itemHttp, QString("Data: %1...").arg(QString::fromStdString(s)), payloadOffset, payloadLen);
            }
        }

    } else if (ip->protocol == 17 && remaining >= sizeof(UDPHeader)) { // UDP
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(trans);
        QTreeWidgetItem* itemUdp = new QTreeWidgetItem(tree);
        itemUdp->setText(0, QString("User Datagram Protocol, Src Port: %1, Dst Port: %2").arg(ntohs(udp->srcPort)).arg(ntohs(udp->destPort)));
        itemUdp->setData(0, Qt::UserRole, transOffset);
        itemUdp->setData(1, Qt::UserRole, 8);

        addTreeItem(itemUdp, QString("Source Port: %1 (0x%2)").arg(ntohs(udp->srcPort)).arg(ntohs(udp->srcPort), 4, 16, QChar('0')), transOffset, 2);
        addTreeItem(itemUdp, QString("Destination Port: %1 (0x%2)").arg(ntohs(udp->destPort)).arg(ntohs(udp->destPort), 4, 16, QChar('0')), transOffset+2, 2);
        addTreeItem(itemUdp, QString("Length: %1 (0x%2)").arg(ntohs(udp->length)).arg(ntohs(udp->length), 4, 16, QChar('0')), transOffset+4, 2);
        addTreeItem(itemUdp, QString("Checksum: 0x%1").arg(ntohs(udp->checkSum), 4, 16, QChar('0')), transOffset+6, 2);

        int payloadOffset = transOffset + 8;
        int payloadLen = totalLen - payloadOffset;
        if (payloadLen > 0) {
            QTreeWidgetItem* itemData = new QTreeWidgetItem(tree);
            itemData->setText(0, QString("Data (%1 bytes)").arg(payloadLen));
            itemData->setData(0, Qt::UserRole, payloadOffset);
            itemData->setData(1, Qt::UserRole, payloadLen);
            std::string s((const char*)(packet+payloadOffset), std::min(payloadLen, 32));
            addTreeItem(itemData, QString("Payload: %1").arg(QString::fromStdString(s)), payloadOffset, payloadLen);
        }

    } else if (ip->protocol == 1 && remaining >= sizeof(ICMPHeader)) { // ICMP
        const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(trans);
        QTreeWidgetItem* itemIcmp = new QTreeWidgetItem(tree);
        itemIcmp->setText(0, "Internet Control Message Protocol");
        itemIcmp->setData(0, Qt::UserRole, transOffset);
        itemIcmp->setData(1, Qt::UserRole, remaining);

        addTreeItem(itemIcmp, QString("Type: %1 (0x%2)").arg((int)icmp->type).arg((int)icmp->type, 2, 16, QChar('0')), transOffset, 1);
        addTreeItem(itemIcmp, QString("Code: %1 (0x%2)").arg((int)icmp->code).arg((int)icmp->code, 2, 16, QChar('0')), transOffset+1, 1);
        addTreeItem(itemIcmp, QString("Checksum: 0x%1").arg(ntohs(icmp->checkSum), 4, 16, QChar('0')), transOffset+2, 2);
    }
}