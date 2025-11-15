#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <optional>

namespace pki487 {

struct PublicKey {
    uint32_t n;
    uint32_t e;
};

// Static map of known public keys. Add entries here as needed.
inline const std::unordered_map<std::string, PublicKey> &known_public_keys() {
    static const std::unordered_map<std::string, PublicKey> m = {
        { "Wurth", { 747139123u, 59166705u } },
        { "Zach",  { 29151883u,  26453285u } }
    };
    return m;
}

// Lookup helper: returns std::nullopt if key not found.
inline std::optional<PublicKey> lookup_public_key(const std::string &name) {
    const auto &m = known_public_keys();
    auto it = m.find(name);
    if (it == m.end()) return std::nullopt;
    return it->second;
}

} // namespace pki487
