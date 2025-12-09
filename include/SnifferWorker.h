// SnifferWorker.h
#include <QObject>
#include <QMutex>
#include "Sniffer.h"

class SnifferWorker : public QObject {
    Q_OBJECT
public:
    SnifferWorker(QString iface) : m_interface(iface) {}

public slots:
    void process() {
        Sniffer sniffer(m_interface.toStdString());
        if (!sniffer.initialize()) {
            emit errorOccurred("Init failed");
            return;
        }

        // 定义回调：当底层捕获包时，发射Qt信号
        auto cb = [this](const struct pcap_pkthdr* pkthdr, const u_char* packet) {
            QString info = QString::fromStdString(PacketParser::parse(pkthdr, packet));
            emit packetCaptured(info);
        };

        // 开始捕获 (这里使用阻塞循环，因为我们在独立线程中)
        sniffer.startCapture(0, cb);
        emit finished();
    }

    signals:
            void packetCaptured(QString info);
    void finished();
    void errorOccurred(QString err);

private:
    QString m_interface;
};

// MainWindow.cpp 片段
void MainWindow::startSniffing() {
    QThread* thread = new QThread;
    SnifferWorker* worker = new SnifferWorker("eth0");

    worker->moveToThread(thread);

    // 连接信号槽
    connect(thread, &QThread::started, worker, &SnifferWorker::process);
    connect(worker, &SnifferWorker::packetCaptured, this, &MainWindow::updateTable);
    connect(worker, &SnifferWorker::finished, thread, &QThread::quit);
    connect(worker, &SnifferWorker::finished, worker, &SnifferWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    thread->start();
}