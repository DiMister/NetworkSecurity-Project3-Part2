#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <climits>

class MathUtils {
public:
    // Load primes from a CSV file that has one prime per line (optional header)
    std::vector<int> loadPrimes(const std::string &path) const;

    // Pick a random element from a vector; returns -1 if empty
    int pickRandomFrom(const std::vector<int>& v) const;

    // Pick a random element from a vector restricted to [minInclusive..maxInclusive]; returns -1 if none match
    int pickRandomFrom(const std::vector<int>& v, int minInclusive, int maxInclusive) const;

    // Find a generator for modulus p
    int findGenerator(int p) const;

    // Find a public exponent 'e' for RSA (utility declaration).
    // Returns 0 on failure.
    uint32_t findPublicExponent(uint32_t totient_n) const;

    uint32_t findGCD(uint32_t a, uint32_t b) const;

    uint32_t extendedEuclidean(uint32_t publicKey, uint32_t totientN) const;

    // RSA sign/verify helpers (lab/demo only)
    // Sign a 32-bit hash using RSA private exponent d and modulus n.
    // Returns numeric signature (0 if n==0).
    uint32_t rsa_sign_uint32(uint32_t hash32, uint32_t d, uint32_t n) const;

    // Verify a 32-bit hash against a numeric signature using RSA public exponent e and modulus n.
    // Returns true if sig^e mod n == (hash32 % n).
    bool rsa_verify_uint32(uint32_t hash32, uint32_t sig, uint32_t e, uint32_t n) const;

private:
    // Check if g is a valid generator for modulus p
    bool isGenerator(int g, int p) const;
};