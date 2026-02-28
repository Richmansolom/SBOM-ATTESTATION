#pragma once

#include <string>
#include <vector>

namespace sbom_demo {
namespace util {

std::vector<std::string> splitWords(const std::string& input);
std::string joinWith(const std::vector<std::string>& parts, const std::string& delim);

}  // namespace util
}  // namespace sbom_demo
