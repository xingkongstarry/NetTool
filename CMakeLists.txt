cmake_minimum_required(VERSION 3.16)
project(NetTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_PREFIX_PATH "E:/program/QT/6.9.0/mingw_64") # 请根据实际情况调整Qt路径

# -----------------------------
# 查找 Qt6
# -----------------------------
find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui Network)
qt_standard_project_setup()

# -----------------------------
# 查找 Python (用于绘图分析)
# -----------------------------
# 请确保路径指向你的Python安装目录
set(Python3_ROOT_DIR "E:/program/python3")
find_package(Python3 REQUIRED COMPONENTS Development)

# -----------------------------
# Windows: 配置 Npcap SDK
# -----------------------------
if(WIN32)
    # 请确保下载并解压了 Npcap SDK 到此目录
    set(PCAP_ROOT "E:/program/npcap-sdk-1.15")

    set(PCAP_INCLUDE_DIR "${PCAP_ROOT}/Include")
    set(PCAP_LIB_DIR     "${PCAP_ROOT}/Lib/x64")

    set(PCAP_LIB_WPCAP   "${PCAP_LIB_DIR}/wpcap.lib")
    set(PCAP_LIB_PACKET  "${PCAP_LIB_DIR}/Packet.lib")

    if(NOT EXISTS "${PCAP_LIB_WPCAP}")
        message(FATAL_ERROR "找不到 wpcap.lib: ${PCAP_LIB_WPCAP}. 请检查 Npcap SDK 路径。")
    endif()

    # 链接 winsock 库
    set(WINSOCK_LIB "ws2_32")
endif()

# -----------------------------
# 源文件定义
# -----------------------------
set(SOURCES
        src/main.cpp
        src/MainWindow.cpp
        src/Sniffer.cpp
        src/Injector.cpp
        src/Parser.cpp
        src/ChecksumUtil.cpp
        src/PythonPlotter.cpp
        # headers included for moc generation
        include/MainWindow.h
        include/Sniffer.h
        include/Injector.h
        include/ProtocolHeaders.h
        include/PythonPlotter.h
)

# -----------------------------
# 生成可执行文件
# -----------------------------
add_executable(NetTool ${SOURCES})

# -----------------------------
# Include 路径
# -----------------------------
target_include_directories(NetTool PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${Python3_INCLUDE_DIRS}
        ${PCAP_INCLUDE_DIR}
)

# -----------------------------
# 链接库
# -----------------------------
target_link_libraries(NetTool PRIVATE
        Qt6::Widgets
        Qt6::Core
        Qt6::Gui
        Qt6::Network
        Python3::Python
        ${PCAP_LIB_WPCAP}
        ${PCAP_LIB_PACKET}
        ${WINSOCK_LIB}
)

# -----------------------------
# Qt Windows DLL 自动复制
# -----------------------------
if(WIN32)
    qt_finalize_executable(NetTool)
endif()