#include "scheduler/display.h"

#include <iostream>
#include <iomanip>

namespace scheduler {

void printDetailedTable(const std::vector<Process>& processes) {
    std::cout << "\nFinal Process Table:\n";
    std::cout << std::left << std::setw(10) << "Process"
              << std::setw(10) << "Active"
              << std::setw(15) << "Arrival Time"
              << std::setw(18) << "Total CPU Time"
              << std::setw(22) << "Remaining CPU Time"
              << std::setw(18) << "Turnaround Time" << "\n";

    for (const auto& p : processes) {
        std::cout << std::left << std::setw(10) << p.name
                  << std::setw(10) << p.active
                  << std::setw(15) << p.arrival
                  << std::setw(18) << p.burst
                  << std::setw(22) << p.remaining
                  << std::setw(18) << p.turnaround << "\n";
    }
}

void printInitialTable(const std::vector<Process>& processes) {
    std::cout << "\nGenerated Process Table:\n";
    std::cout << std::left << std::setw(10) << "Process"
              << std::setw(15) << "Arrival Time"
              << std::setw(15) << "CPU Time" << "\n";
    for (const auto& p : processes) {
        std::cout << std::left << std::setw(10) << p.name
                  << std::setw(15) << p.arrival
                  << std::setw(15) << p.burst << "\n";
    }
}

}  // namespace scheduler
