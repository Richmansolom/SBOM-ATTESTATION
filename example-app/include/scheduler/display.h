#pragma once

#include "scheduler/process.h"
#include <vector>

namespace scheduler {

void printDetailedTable(const std::vector<Process>& processes);
void printInitialTable(const std::vector<Process>& processes);

}  // namespace scheduler
