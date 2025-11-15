#pragma once
#include <string>
#include <vector>

namespace pki487 {

// Hex encode raw bytes (lowercase) -> e.g. {0x0A,0xFF} -> "0aff"
std::string hex_encode(const std::vector<unsigned char>& data);

// Decode hex string (accepts upper/lowercase) into bytes. Throws std::runtime_error on invalid input.
std::vector<unsigned char> hex_decode(const std::string& hex);

} // namespace pki487
