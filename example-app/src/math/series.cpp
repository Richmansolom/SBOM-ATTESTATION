#include "math/series.h"

#include "util/string_util.h"

namespace sbom_demo {
namespace math {

std::vector<int> fibonacci(int count) {
  std::vector<int> values;
  if (count <= 0) return values;
  values.push_back(0);
  if (count == 1) return values;
  values.push_back(1);
  for (int i = 2; i < count; ++i) {
    values.push_back(values[i - 1] + values[i - 2]);
  }
  return values;
}

std::string formatSeries(const std::vector<int>& values) {
  std::vector<std::string> parts;
  parts.reserve(values.size());
  for (int value : values) {
    parts.push_back(std::to_string(value));
  }
  return sbom_demo::util::joinWith(parts, ",");
}

}  // namespace math
}  // namespace sbom_demo
