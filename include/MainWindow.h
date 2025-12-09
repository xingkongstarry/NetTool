#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QTabWidget>
#include <QThread>
#include <QTreeWidget>
#include <QSplitter>
#include <QTextEdit>
#include <vector>
#include "Sniffer.h"
#include "Injector.h"

class SnifferWorker : public QObject {
Q_OBJECT
public:
    SnifferWorker(std::string dev, std::string filt) : device(dev), filter(filt) {}
    void process();
    void stop() { m_sniffer.stopCapture(); }
signals:
    void packetCaptured(QString srcIp, QString dstIp, QString proto, QString info, int len, QByteArray rawData);
    void finished();
private:
    std::string device;
    std::string filter;
    Sniffer m_sniffer;
};

class MainWindow : public QMainWindow {
Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartSniff();
    void onStopSniff();
    void onPacketCaptured(QString srcIp, QString dstIp, QString proto, QString info, int len, QByteArray rawData);
    void onSendPacket();
    void onAnalyze();
    void onTablePacketClicked(int row, int col);
    void onTreeItemHovered(QTreeWidgetItem* item, int column);

private:
    void setupUi();
    void updateInterfaceList();
    void showHexDump(const std::vector<uint8_t>& data);

    QTabWidget* tabWidget;

    QComboBox* comboInterfaces;
    QLineEdit* lineEditFilter;
    QPushButton* btnStartSniff;
    QPushButton* btnStopSniff;
    QPushButton* btnAnalyze;

    QSplitter* mainSplitter;
    QSplitter* detailSplitter;
    QTableWidget* tablePackets;
    QTreeWidget* treeDetails;
    QTextEdit* hexView;

    // Injector
    QLineEdit* lineSrcIP;
    QLineEdit* lineDstIP;
    QLineEdit* lineSrcMac;
    QLineEdit* lineDstMac;
    QLineEdit* lineSrcPort;
    QLineEdit* lineDstPort;
    QComboBox* comboProto;
    QLineEdit* linePayload;
    QPushButton* btnSend;

    QThread* snifferThread;
    SnifferWorker* snifferWorker;

    std::vector<int> capturedSizes;
    std::vector<std::vector<uint8_t>> m_allPackets;
    Injector injector;
};

#endif