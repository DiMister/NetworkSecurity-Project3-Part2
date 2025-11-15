#include "encoding.hpp"
#include <stdexcept>
#include <cctype>

namespace pki487 {

static inline unsigned char hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    throw std::runtime_error("Invalid hex digit");
}

std::string hex_encode(const std::vector<unsigned char>& data) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char b : data) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

std::vector<unsigned char> hex_decode(const std::string& hex) {
    std::vector<unsigned char> out;
    size_t len = hex.size();
    if (len % 2 != 0) throw std::runtime_error("Hex string must have even length");
    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        unsigned char hi = hexval(hex[i]);
        unsigned char lo = hexval(hex[i+1]);
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return out;
}

} // namespace pki487
