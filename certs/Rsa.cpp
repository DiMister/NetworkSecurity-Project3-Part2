#include <cstdint>
#include <iostream>
#include "Rsa.hpp"
#include "../Helpers/MathUtils.hpp"
#include <tuple>
#include <vector>
#include <sstream>
#include <stdexcept>

namespace pki487 {
Rsa::Rsa() {
    auto [p,q] = PickPrimes();
    auto [n,e,d] = GenerateKeypair(p, q);
    publicKey = {n, e};
    privateKey = {n, d};
}

std::pair<uint32_t, uint32_t> Rsa::PickPrimes() {
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");

    if (primes.size() < 2) {
        std::cerr << "Not enough primes in primes.csv\n";
        return {};
    }

    // Generate RSA keypair for client (small primes from CSV)
    uint32_t p_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    uint32_t q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    while (q_rsa == p_rsa) q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));

    printf("Client: generated RSA primes p=%u q=%u\n", p_rsa, q_rsa);
    return {p_rsa, q_rsa};
}


std::tuple<uint32_t, uint32_t, uint32_t> Rsa::GenerateKeypair(uint32_t p_rsa, uint32_t q_rsa) {
    MathUtils mathUtils;
    unsigned long long n_tmp = static_cast<unsigned long long>(p_rsa) * static_cast<unsigned long long>(q_rsa);
    uint32_t n = static_cast<uint32_t>(n_tmp);
    uint32_t totient = (p_rsa - 1u) * (q_rsa - 1u);

    printf("Client: computed RSA modulus n=%u totient=%u\n", n, totient);

    uint32_t e = mathUtils.findPublicExponent(totient);
    if (e == 0u) {
        e = 65537u;
        if (mathUtils.findGCD(e, totient) != 1u) {
            std::cerr << "Failed to find suitable public exponent\n";
            return {};
        }
    }

    printf("Client: selected public exponent e=%u\n", e);

    uint32_t d = mathUtils.extendedEuclidean(e, totient);
    printf("Client: computed private exponent d=%u\n", d);

    return {n, e, d};
}

// Fast modular exponentiation (binary exponentiation)
uint32_t Rsa::mod_pow(uint32_t base, uint32_t exp, uint32_t mod) {
    if (mod == 0) throw std::runtime_error("modulo 0 in mod_pow");
    uint64_t result = 1;
    uint64_t b = base % mod;
    uint32_t e = exp;
    while (e > 0) {
        if (e & 1u) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1u;
    }
    return static_cast<uint32_t>(result);
}

// asked chat-gpt to make a simple hash function to replace cbc because I didn't realize cbc could work
// now it just less convient to remove this
// Simple message digest: produce an integer in [0, mod-1]. This is NOT cryptographically strong
uint32_t Rsa::compute_digest(const std::string& msg, uint32_t mod) {
    if (mod == 0) return 0;
    // A simple rolling accumulator mixing byte values and positions
    uint64_t acc = 1469598103934665603ULL; // FNV offset basis
    for (size_t i = 0; i < msg.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(msg[i]);
        acc ^= (uint64_t)(c + 0x9e);
        acc *= 1099511628211ULL; // FNV prime
        acc += (i + 1);
    }
    // Fold into 32-bit and reduce modulo mod
    uint32_t folded = static_cast<uint32_t>((acc >> 32) ^ (acc & 0xffffffffULL));
    return static_cast<uint32_t>(folded % (mod == 0 ? 1u : mod));
}

static std::vector<unsigned char> uint32_to_be_bytes(uint32_t v) {
    std::vector<unsigned char> out(4);
    out[0] = static_cast<unsigned char>((v >> 24) & 0xFF);
    out[1] = static_cast<unsigned char>((v >> 16) & 0xFF);
    out[2] = static_cast<unsigned char>((v >> 8) & 0xFF);
    out[3] = static_cast<unsigned char>((v) & 0xFF);
    return out;
}

static uint32_t be_bytes_to_uint32(const std::vector<unsigned char>& b) {
    uint32_t v = 0;
    for (size_t i = 0; i < b.size() && i < 4; ++i) {
        v = (v << 8) | static_cast<uint32_t>(b[i]);
    }
    // If provided fewer than 4 bytes, the loop still works (assumes big-endian input)
    return v;
}

std::vector<unsigned char> Rsa::sign_message(const std::string& tbs, const keypair& priv) {
    uint32_t n = priv.n;
    uint32_t d = priv.exponent;
    if (n == 0) throw std::runtime_error("Invalid modulus for signing");
    uint32_t digest = compute_digest(tbs, n);
    uint32_t sig = mod_pow(digest, d, n);
    return uint32_to_be_bytes(sig);
}

bool Rsa::verify_message(const std::string& tbs, const keypair& pub, const std::vector<unsigned char>& sig_bytes) {
    uint32_t n = pub.n;
    uint32_t e = pub.exponent;
    if (n == 0) return false;
    uint32_t sig = be_bytes_to_uint32(sig_bytes);
    uint32_t recovered = mod_pow(sig, e, n);
    uint32_t expect = compute_digest(tbs, n);
    return recovered == expect;
}

// Numeric helpers: encrypt/decrypt/sign/verify for 32-bit values (demo only)
uint32_t Rsa::encrypt_uint32(uint32_t m, const keypair& pub) {
    if (pub.n == 0) throw std::runtime_error("Invalid public modulus");
    return mod_pow(m % pub.n, pub.exponent, pub.n);
}

uint32_t Rsa::decrypt_uint32(uint32_t c, const keypair& priv) {
    if (priv.n == 0) throw std::runtime_error("Invalid private modulus");
    return mod_pow(c % priv.n, priv.exponent, priv.n);
}

uint32_t Rsa::sign_uint32(uint32_t m, const keypair& priv) {
    if (priv.n == 0) throw std::runtime_error("Invalid private modulus");
    return mod_pow(m % priv.n, priv.exponent, priv.n);
}

bool Rsa::verify_uint32(uint32_t m, uint32_t sig, const keypair& pub) {
    if (pub.n == 0) return false;
    uint32_t recovered = mod_pow(sig, pub.exponent, pub.n);
    return recovered == static_cast<uint32_t>(m % pub.n);
}

} // namespace pki487