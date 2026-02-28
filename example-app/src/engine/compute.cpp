#include "engine/compute.h"

#include "math/series.h"
#include "util/string_util.h"

namespace sbom_demo {
namespace engine {

std::string buildReport(int count) {
  auto series = sbom_demo::math::fibonacci(count);
  auto seriesText = sbom_demo::math::formatSeries(series);
  auto words = sbom_demo::util::splitWords("SBOM Demo Report");
  return sbom_demo::util::joinWith(words, " ") + ": [" + seriesText + "]";
}

}  // namespace engine
}  // namespace sbom_demo
