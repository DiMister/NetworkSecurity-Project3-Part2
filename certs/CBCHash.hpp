#ifndef CBCHASH_HPP
#define CBCHASH_HPP

#include "../Helpers/SDESModes.hpp"
#include <bitset>
#include <vector>
#include <cstddef>

class CBCHash {
public:
	// Construct with a 10-bit S-DES key and an 8-bit IV (defaults match previous demo)
	CBCHash(const std::bitset<10>& key = std::bitset<10>("1000000000"),
			const std::bitset<8>& iv = std::bitset<8>("00000000"));

	// Setters / getters
	void setKey(const std::bitset<10>& key);
	std::bitset<10> getKey() const;

	void setIV(const std::bitset<8>& iv);
	std::bitset<8> getIV() const;

	// Hash a vector of 8-bit blocks directly
	std::bitset<8> hash(const std::vector<bool>& bits);

	std::bitset<8> hash(const std::vector<std::bitset<8>>& blocks);

private:
	std::bitset<10> key_;
	std::bitset<8> iv_;
	SDESModes sdes_; // helper for S-DES operations
};

// No template implementations; runtime-size overloads are implemented in the .cpp

#endif // CBCHASH_HPP
