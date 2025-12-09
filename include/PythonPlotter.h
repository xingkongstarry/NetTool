#ifndef PYTHONPLOTTER_H
#define PYTHONPLOTTER_H
#include <vector>

class PythonPlotter {
public:
    static void plotPacketSizes(const std::vector<int>& sizes);
};
#endif