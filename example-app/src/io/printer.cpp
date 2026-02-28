#include "io/printer.h"

#include "engine/compute.h"

namespace sbom_demo {
namespace io {

std::string renderOutput(int count) {
  return "Output => " + sbom_demo::engine::buildReport(count);
}

}  // namespace io
}  // namespace sbom_demo
