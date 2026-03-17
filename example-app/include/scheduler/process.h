#pragma once

#include <string>
#include <vector>

namespace scheduler {

struct Process {
    std::string name;
    int arrival;
    int burst;
    int remaining;
    int completion;
    int turnaround;
    int start;
    int active;

    Process(std::string n, int a, int b);
};

std::vector<Process> generateProcesses(int n, int k, double d, double v);

}  // namespace scheduler
