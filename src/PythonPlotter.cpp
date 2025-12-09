#include "PythonPlotter.h"
#include <Python.h>
#include <iostream>

void PythonPlotter::plotPacketSizes(const std::vector<int>& sizes) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
    }

    // 将C++ vector 转为 Python List
    PyObject* pList = PyList_New(sizes.size());
    for (size_t i = 0; i < sizes.size(); ++i) {
        PyList_SetItem(pList, i, PyLong_FromLong(sizes[i]));
    }

    PyObject* mainModule = PyImport_AddModule("__main__");
    PyObject* globalDict = PyModule_GetDict(mainModule);
    PyDict_SetItemString(globalDict, "data_sizes", pList);

    const char* script = R"(
import matplotlib.pyplot as plt
try:
    plt.figure(figsize=(8, 5))
    plt.hist(data_sizes, bins=20, color='skyblue', edgecolor='black')
    plt.title('Packet Size Distribution')
    plt.xlabel('Bytes')
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.show()
except Exception as e:
    print(f"Python Plot Error: {e}")
    )";

    PyRun_SimpleString(script);

    // 注意：Py_Finalize() 在嵌入式环境中频繁调用可能导致问题，通常在程序退出时调用
    // 这里为了演示简单保留，实际可放在main的析构中
}