#include <QApplication>
#include "MainWindow.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

void setupConsole() {
#ifdef _WIN32
    // 分配一个新的控制台窗口
    if (AllocConsole()) {
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        std::ios::sync_with_stdio(true);
        std::cout << "=== NetTool Debug Console Started ===" << std::endl;
    }
#endif
}

int main(int argc, char *argv[]) {
    setupConsole(); // 启动控制台

    std::cout << "[Main] Application starting..." << std::endl;

    QApplication app(argc, argv);

    MainWindow window;
    window.show();

    std::cout << "[Main] MainWindow shown." << std::endl;

    return app.exec();
}