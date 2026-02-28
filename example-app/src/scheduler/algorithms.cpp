#include "scheduler/algorithms.h"
#include "scheduler/display.h"

#include <algorithm>
#include <iostream>

namespace scheduler {

double fifoScheduling(std::vector<Process> processes) {
    std::sort(processes.begin(), processes.end(),
              [](const Process& a, const Process& b) { return a.arrival < b.arrival; });
    int time = 0, totalTAT = 0;
    std::cout << "\nFIFO Gantt Chart:\n0 ";
    for (auto& p : processes) {
        if (time < p.arrival) time = p.arrival;
        std::cout << "| " << p.name << " | " << time + p.burst << " ";
        time += p.burst;
        p.completion = time;
        p.remaining = 0;
        p.turnaround = p.completion - p.arrival;
        totalTAT += p.turnaround;
        p.active = 0;
    }
    std::cout << "\n";
    printDetailedTable(processes);
    return static_cast<double>(totalTAT) / processes.size();
}

double sjfScheduling(std::vector<Process> processes) {
    int time = 0, totalTAT = 0;
    int n = static_cast<int>(processes.size());
    int completed = 0;

    std::cout << "\nSJF Gantt Chart:\n0 ";
    while (completed < n) {
        std::vector<int> ready;
        for (int i = 0; i < n; ++i)
            if (processes[i].arrival <= time && processes[i].remaining > 0)
                ready.push_back(i);

        if (ready.empty()) { ++time; continue; }

        std::sort(ready.begin(), ready.end(),
                  [&processes](int a, int b) { return processes[a].burst < processes[b].burst; });

        int idx = ready.front();
        Process& p = processes[idx];
        if (time < p.arrival) time = p.arrival;
        std::cout << "| " << p.name << " | " << time + p.burst << " ";
        time += p.burst;
        p.completion = time;
        p.turnaround = p.completion - p.arrival;
        p.remaining = 0;
        p.active = 0;
        totalTAT += p.turnaround;
        ++completed;
    }
    std::cout << "\n";
    printDetailedTable(processes);
    return static_cast<double>(totalTAT) / n;
}

double srtScheduling(std::vector<Process> processes) {
    int time = 0, totalTAT = 0, complete = 0;
    int n = static_cast<int>(processes.size());
    std::cout << "\nSRT Gantt Chart:\n0 ";

    while (complete != n) {
        int shortest = -1;
        for (int j = 0; j < n; ++j) {
            if (processes[j].arrival <= time && processes[j].remaining > 0) {
                if (shortest == -1 ||
                    processes[j].remaining < processes[shortest].remaining)
                    shortest = j;
            }
        }

        if (shortest == -1) { ++time; continue; }

        std::cout << "| " << processes[shortest].name << " ";
        int orig_arrival = processes[shortest].arrival;

        while (processes[shortest].remaining > 0) {
            ++time;
            --processes[shortest].remaining;
            bool preempt = false;
            for (int j = 0; j < n; ++j) {
                if (j != shortest && processes[j].arrival == time &&
                    processes[j].remaining > 0 &&
                    processes[j].remaining < processes[shortest].remaining) {
                    preempt = true;
                    break;
                }
            }
            if (preempt) break;
        }
        std::cout << "| " << time << " ";

        if (processes[shortest].remaining == 0) {
            processes[shortest].completion = time;
            processes[shortest].turnaround = time - orig_arrival;
            processes[shortest].active = 0;
            totalTAT += processes[shortest].turnaround;
            ++complete;
        }
    }
    std::cout << "\n";
    printDetailedTable(processes);
    return static_cast<double>(totalTAT) / n;
}

}  // namespace scheduler
