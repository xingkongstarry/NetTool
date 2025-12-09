#include "MainWindow.h"
#include "Parser.h"
#include "PythonPlotter.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QMessageBox>
#include <QFormLayout>
#include <QMetaObject>
#include <QApplication>
#include <iostream>
#include <QColor>
#include <QFontDatabase>

void SnifferWorker::process() {
    std::cout << "[Worker] Starting. Device: " << device << " Filter: " << filter << std::endl;
    if (!m_sniffer.openDevice(device)) {
        QString errorMsg = QString("打开网卡失败: %1").arg(QString::fromStdString(device));
        QMetaObject::invokeMethod(qApp, [=](){ QMessageBox::critical(nullptr, "Error", errorMsg); });
        emit finished(); return;
    }
    if (!filter.empty()) m_sniffer.setFilter(filter);
    auto cb = [&](const struct pcap_pkthdr* header, const u_char* pkt_data) {
        auto info = PacketParser::parse(header, pkt_data);
        QByteArray rawData((const char*)pkt_data, header->len);
        emit packetCaptured(QString::fromStdString(info.srcIP), QString::fromStdString(info.dstIP),
                            QString::fromStdString(info.protocol), QString::fromStdString(info.info), info.length, rawData);
    };
    m_sniffer.startCapture(cb);
    emit finished();
}

// MainWindow
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), snifferThread(nullptr), snifferWorker(nullptr) {
    setupUi();
    updateInterfaceList();
    resize(1200, 900);
    setWindowTitle("NetTool - Wireshark Clone");
}

MainWindow::~MainWindow() {
    onStopSniff();
}

void MainWindow::setupUi() {
    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

    tabWidget = new QTabWidget();

    QWidget* tabSniffer = new QWidget();
    QVBoxLayout* layoutSniffer = new QVBoxLayout(tabSniffer);
    QHBoxLayout* controlLayout = new QHBoxLayout();

    comboInterfaces = new QComboBox(); comboInterfaces->setMinimumWidth(300);
    lineEditFilter = new QLineEdit(); lineEditFilter->setPlaceholderText("BPF Filter (e.g. icmp)");
    btnStartSniff = new QPushButton("Start");
    btnStopSniff = new QPushButton("Stop"); btnStopSniff->setEnabled(false);
    btnAnalyze = new QPushButton("Stats");

    controlLayout->addWidget(new QLabel("Interface:")); controlLayout->addWidget(comboInterfaces, 1);
    controlLayout->addWidget(new QLabel("Filter:")); controlLayout->addWidget(lineEditFilter, 1);
    controlLayout->addWidget(btnStartSniff); controlLayout->addWidget(btnStopSniff); controlLayout->addWidget(btnAnalyze);

    mainSplitter = new QSplitter(Qt::Vertical);
    tablePackets = new QTableWidget();
    tablePackets->setColumnCount(5);
    tablePackets->setHorizontalHeaderLabels({"Source", "Destination", "Protocol", "Info", "Length"});
    tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);

    detailSplitter = new QSplitter(Qt::Vertical);
    treeDetails = new QTreeWidget();
    treeDetails->setColumnCount(1);
    treeDetails->setHeaderHidden(true);
    treeDetails->setMouseTracking(true);

    hexView = new QTextEdit();
    hexView->setReadOnly(true);
    const QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    hexView->setFont(fixedFont);

    detailSplitter->addWidget(treeDetails); detailSplitter->addWidget(hexView);
    detailSplitter->setStretchFactor(0, 2); detailSplitter->setStretchFactor(1, 1);
    mainSplitter->addWidget(tablePackets); mainSplitter->addWidget(detailSplitter);
    mainSplitter->setStretchFactor(0, 1); mainSplitter->setStretchFactor(1, 2);

    layoutSniffer->addLayout(controlLayout); layoutSniffer->addWidget(mainSplitter);

    QWidget* tabInjector = new QWidget();
    QFormLayout* formLayout = new QFormLayout(tabInjector);
    lineSrcIP = new QLineEdit("10.56.171.105");
    lineDstIP = new QLineEdit("10.56.0.1");
    // 增加 Source MAC 输入框，填入你本机真实的 MAC
    lineSrcMac = new QLineEdit("A0:29:42:F5:1A:8B"); // <--- 必须是这个，冒号格式
    lineDstMac = new QLineEdit("14:14:4b:6b:29:b9");
    lineSrcPort = new QLineEdit("12345");
    lineDstPort = new QLineEdit("80");
    comboProto = new QComboBox();
    comboProto->addItems({"TCP (SYN)", "UDP", "ICMP (Ping)"});
    linePayload = new QLineEdit("Hello Network");
    btnSend = new QPushButton("Send Packet");

    formLayout->addRow("Source IP:", lineSrcIP); formLayout->addRow("Dest IP:", lineDstIP);
    formLayout->addRow("Source MAC:", lineSrcMac); // 添加到界面
    formLayout->addRow("Dest MAC:", lineDstMac);
    formLayout->addRow("Protocol:", comboProto);
    formLayout->addRow("Source Port:", lineSrcPort); formLayout->addRow("Dest Port:", lineDstPort);
    formLayout->addRow("UDP Payload:", linePayload); formLayout->addRow(btnSend);

    tabWidget->addTab(tabSniffer, "Sniffer");
    tabWidget->addTab(tabInjector, "Injector");
    mainLayout->addWidget(tabWidget);

    connect(btnStartSniff, &QPushButton::clicked, this, &MainWindow::onStartSniff);
    connect(btnStopSniff, &QPushButton::clicked, this, &MainWindow::onStopSniff);
    connect(btnSend, &QPushButton::clicked, this, &MainWindow::onSendPacket);
    connect(btnAnalyze, &QPushButton::clicked, this, &MainWindow::onAnalyze);

    connect(tablePackets, &QTableWidget::cellClicked, this, &MainWindow::onTablePacketClicked);
    connect(treeDetails, &QTreeWidget::itemEntered, this, &MainWindow::onTreeItemHovered);
    connect(treeDetails, &QTreeWidget::itemClicked, this, &MainWindow::onTreeItemHovered);
}


void MainWindow::updateInterfaceList() {
    auto devs = Sniffer::getAllDevices();
    comboInterfaces->clear();
    for (const auto& d : devs) {
        QString label = QString::fromStdString(d.second);
        if (label.isEmpty()) label = QString::fromStdString(d.first);
        comboInterfaces->addItem(label, QString::fromStdString(d.first));
    }
}

void MainWindow::onStartSniff() {
    if (comboInterfaces->currentIndex() < 0) return;
    tablePackets->setRowCount(0); treeDetails->clear(); hexView->clear();
    m_allPackets.clear(); capturedSizes.clear();

    std::string devName = comboInterfaces->currentData().toString().toStdString();
    std::string filterExp = lineEditFilter->text().toStdString();

    snifferThread = new QThread;
    snifferWorker = new SnifferWorker(devName, filterExp);
    snifferWorker->moveToThread(snifferThread);

    connect(snifferThread, &QThread::started, snifferWorker, &SnifferWorker::process);
    connect(snifferWorker, &SnifferWorker::packetCaptured, this, &MainWindow::onPacketCaptured);
    connect(snifferWorker, &SnifferWorker::finished, snifferThread, &QThread::quit);
    connect(snifferWorker, &SnifferWorker::finished, snifferWorker, &QObject::deleteLater);
    connect(snifferThread, &QThread::finished, snifferThread, &QObject::deleteLater);
    connect(snifferWorker, &SnifferWorker::finished, this, [=, this](){ btnStartSniff->setEnabled(true); btnStopSniff->setEnabled(false); });

    snifferThread->start();
    btnStartSniff->setEnabled(false); btnStopSniff->setEnabled(true);
}
void MainWindow::onStopSniff() { if(snifferWorker) snifferWorker->stop(); }
void MainWindow::onAnalyze() { if(!capturedSizes.empty()) PythonPlotter::plotPacketSizes(capturedSizes); }

void MainWindow::onPacketCaptured(QString srcIp, QString dstIp, QString proto, QString info, int len, QByteArray rawData) {
    int row = tablePackets->rowCount();
    tablePackets->insertRow(row);

    QTableWidgetItem* itemSrc = new QTableWidgetItem(srcIp);
    QTableWidgetItem* itemDst = new QTableWidgetItem(dstIp);
    QTableWidgetItem* itemProto = new QTableWidgetItem(proto);
    QTableWidgetItem* itemInfo = new QTableWidgetItem(info);
    QTableWidgetItem* itemLen = new QTableWidgetItem(QString::number(len));

    QColor bgColor = Qt::white;
    if (proto == "TCP" || proto == "HTTP") bgColor = QColor(200, 240, 200);
    else if (proto == "UDP") bgColor = QColor(200, 225, 255);
    else if (proto == "ICMP") bgColor = QColor(240, 200, 240);
    else if (proto == "ARP") bgColor = QColor(250, 240, 180);
    else if (proto.contains("Error")) { bgColor = QColor(255, 64, 64); itemProto->setForeground(Qt::white); }

    itemSrc->setBackground(bgColor); itemDst->setBackground(bgColor);
    itemProto->setBackground(bgColor); itemInfo->setBackground(bgColor); itemLen->setBackground(bgColor);

    tablePackets->setItem(row, 0, itemSrc); tablePackets->setItem(row, 1, itemDst);
    tablePackets->setItem(row, 2, itemProto); tablePackets->setItem(row, 3, itemInfo);
    tablePackets->setItem(row, 4, itemLen);

    std::vector<uint8_t> vec(rawData.begin(), rawData.end());
    m_allPackets.push_back(vec);
    capturedSizes.push_back(len);
}

// 发包逻辑
void MainWindow::onSendPacket() {
    if (comboInterfaces->currentIndex() < 0) return;
    std::string devName = comboInterfaces->currentData().toString().toStdString();
    if (!injector.openDevice(devName)) { QMessageBox::critical(this, "Error", "Failed open device"); return; }

    bool success = false;
    QString proto = comboProto->currentText();
    std::string sip = lineSrcIP->text().toStdString(); std::string dip = lineDstIP->text().toStdString();
    std::string dmac = lineDstMac->text().toStdString();
    // 获取 Source MAC
    std::string smac = lineSrcMac->text().toStdString();

    if (proto.startsWith("TCP")) success = injector.sendTCP(sip, dip, lineSrcPort->text().toInt(), lineDstPort->text().toInt(), smac, dmac);
    else if (proto.startsWith("UDP")) success = injector.sendUDP(sip, dip, lineSrcPort->text().toInt(), lineDstPort->text().toInt(), linePayload->text().toStdString(), smac, dmac);
    else if (proto.startsWith("ICMP")) success = injector.sendICMP(sip, dip, smac, dmac);

    if(success) QMessageBox::information(this, "OK", "Packet sent successfully!");
    else QMessageBox::warning(this, "Fail", "Packet failed to send (Check your Source MAC!)");

    injector.closeDevice();
}

void MainWindow::onTablePacketClicked(int row, int col) {
    if (row < 0 || row >= m_allPackets.size()) return;
    const std::vector<uint8_t>& data = m_allPackets[row];
    PacketParser::analyzeToTree(data, treeDetails);
    showHexDump(data);
}

void MainWindow::showHexDump(const std::vector<uint8_t>& data) {
    QString hexStr;
    int len = data.size();
    for (int i = 0; i < len; ++i) {
        QString byteStr = QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper();
        hexStr += byteStr + " ";
    }
    hexView->setPlainText(hexStr);
}

void MainWindow::onTreeItemHovered(QTreeWidgetItem* item, int column) {
    if (!item) return;
    QVariant vOffset = item->data(0, Qt::UserRole);
    QVariant vLen = item->data(1, Qt::UserRole);
    if (!vOffset.isValid() || !vLen.isValid()) return;
    int offset = vOffset.toInt();
    int len = vLen.toInt();
    int charStart = offset * 3;
    int charLen = (len * 3) - 1;
    if (charLen <= 0) return;
    QTextCursor cursor = hexView->textCursor();
    cursor.clearSelection();
    cursor.setPosition(charStart);
    cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, charLen);
    QTextCharFormat fmt;
    fmt.setBackground(QColor(0, 0, 139));
    fmt.setForeground(Qt::white);
    QTextCursor allCursor = hexView->textCursor();
    allCursor.select(QTextCursor::Document);
    QTextCharFormat normalFmt;
    normalFmt.setBackground(Qt::white);
    normalFmt.setForeground(Qt::black);
    allCursor.setCharFormat(normalFmt);
    cursor.setCharFormat(fmt);
}