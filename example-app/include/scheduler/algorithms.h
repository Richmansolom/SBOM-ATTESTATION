#pragma once

#include "scheduler/process.h"
#include <vector>

namespace scheduler {

double fifoScheduling(std::vector<Process> processes);
double sjfScheduling(std::vector<Process> processes);
double srtScheduling(std::vector<Process> processes);

}  // namespace scheduler
