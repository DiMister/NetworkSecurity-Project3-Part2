#pragma once
#include <string>
#include <vector>

namespace pki487 {

std::string read_text_file(const std::string& path);
void write_text_file(const std::string& path, const std::string& content);

// Trim whitespace from both ends
std::string trim(const std::string& s);

// Split string by delimiter into vector (no empty entries unless allow_empty)
std::vector<std::string> split(const std::string& s, char delim, bool allow_empty = false);

// Normalize newlines to \n and strip trailing spaces on each line for canonicalization.
std::string canonicalize_newlines(const std::string& s);

} // namespace pki487
