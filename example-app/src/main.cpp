#include <iostream>
#include <iomanip>

#include "scheduler/process.h"
#include "scheduler/algorithms.h"
#include "scheduler/display.h"

int main() {
    const int n = 10;    // Number of processes
    const int k = 20;     // Arrival time window [0, 20]
    const double d = 10;  // Mean burst time
    const double v = 5;   // Std dev for burst time

    std::vector<scheduler::Process> baseProcesses =
        scheduler::generateProcesses(n, k, d, v);

    scheduler::printInitialTable(baseProcesses);

    double fifoAvg = scheduler::fifoScheduling(baseProcesses);
    double sjfAvg = scheduler::sjfScheduling(baseProcesses);
    double srtAvg = scheduler::srtScheduling(baseProcesses);

    std::cout << "\n--- Comparative Analysis ---\n";
    std::cout << std::left << std::setw(10) << "Algorithm"
              << std::setw(25) << "Avg Turnaround Time" << "\n";
    std::cout << std::setw(10) << "FIFO" << std::setw(25) << fifoAvg << "\n";
    std::cout << std::setw(10) << "SJF" << std::setw(25) << sjfAvg << "\n";
    std::cout << std::setw(10) << "SRT" << std::setw(25) << srtAvg << "\n";

    return 0;
}
