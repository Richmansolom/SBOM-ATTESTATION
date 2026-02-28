#include "util/string_util.h"

#include <sstream>

namespace sbom_demo {
namespace util {

std::vector<std::string> splitWords(const std::string& input) {
  std::istringstream iss(input);
  std::vector<std::string> parts;
  std::string word;
  while (iss >> word) {
    parts.push_back(word);
  }
  return parts;
}

std::string joinWith(const std::vector<std::string>& parts, const std::string& delim) {
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    oss << parts[i];
    if (i + 1 < parts.size()) {
      oss << delim;
    }
  }
  return oss.str();
}

}  // namespace util
}  // namespace sbom_demo
