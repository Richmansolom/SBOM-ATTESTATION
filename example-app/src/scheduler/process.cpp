#include "scheduler/process.h"

#include <random>

namespace scheduler {

Process::Process(std::string n, int a, int b)
    : name(std::move(n)), arrival(a), burst(b), remaining(b), completion(0),
      turnaround(0), start(-1), active(1) {}

std::vector<Process> generateProcesses(int n, int k, double d, double v) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> arrivalDist(0, k);
    std::normal_distribution<> burstDist(d, v);

    std::vector<Process> processes;
    processes.reserve(n);
    for (int i = 0; i < n; ++i) {
        int arrival = arrivalDist(gen);
        int burst;
        do {
            burst = static_cast<int>(burstDist(gen));
        } while (burst <= 0);
        processes.emplace_back("P" + std::to_string(i + 1), arrival, burst);
    }
    return processes;
}

}  // namespace scheduler
