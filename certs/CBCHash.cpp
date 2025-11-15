#include "CBCHash.hpp"
#include <iostream>
#include <string>
#include <vector>

CBCHash::CBCHash(const std::bitset<10>& key, const std::bitset<8>& iv)
    : key_(key), iv_(iv), sdes_(key) {}

void CBCHash::setKey(const std::bitset<10>& key) {
    key_ = key;
    // Reinitialize SDESModes with new key
    sdes_ = SDESModes(key_);
}

std::bitset<10> CBCHash::getKey() const { return key_; }

void CBCHash::setIV(const std::bitset<8>& iv) { iv_ = iv; }

std::bitset<8> CBCHash::getIV() const { return iv_; }

std::bitset<8> CBCHash::hash(const std::vector<std::bitset<8>>& blocks) {
    if (blocks.empty()) {
        // For empty input return IV as a sensible default
        return iv_;
    }

    auto ct = sdes_.encrypt(blocks, EncryptionMode::CBC, iv_);
    if (ct.empty()) return std::bitset<8>(0);
    return ct.back();
}

std::bitset<8> CBCHash::hash(const std::vector<bool>& bits) {
    // Convert dynamic-size bit vector into 8-bit blocks (LSB-first within each byte)
    std::size_t totalBits = bits.size();
    std::size_t numBlocks = (totalBits + 7) / 8;
    std::vector<std::bitset<8>> blocks;
    blocks.reserve(numBlocks);

    for (std::size_t i = 0; i < numBlocks; ++i) {
        std::bitset<8> b(0);
        for (std::size_t bit = 0; bit < 8; ++bit) {
            std::size_t idx = i * 8 + bit; // bit 0 is LSB
            if (idx < totalBits) {
                b[bit] = bits[idx];
            } else {
                b[bit] = 0;
            }
        }
        blocks.push_back(b);
    }

    return hash(blocks);
}