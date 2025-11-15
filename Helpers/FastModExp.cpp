#include "FastModExp.h"
#include <stdexcept>

// Use wider intermediate when available; unsigned version
uint32_t FastModExp::mul_mod(uint32_t a, uint32_t b, uint32_t mod) {
    // Use 64-bit intermediate to reduce overflow risk
    unsigned long long res = static_cast<unsigned long long>(a) * static_cast<unsigned long long>(b);
    return static_cast<uint32_t>(res % mod);
}

uint32_t FastModExp::powmod(uint32_t base, uint32_t exp, uint32_t mod) {
    if (mod == 0) throw std::invalid_argument("mod must be > 0");

    base %= mod;
    uint32_t result = 1u;

    // Find the most-significant-bit mask for exp
    uint32_t mask = 1u;
    uint32_t e = exp;
    while (e >>= 1) mask <<= 1;

    // Process bits from MSB to LSB
    for (; mask; mask >>= 1) {
        result = mul_mod(result, result, mod);
        if (exp & mask) {
            result = mul_mod(result, base, mod);
        }
    }

    return result;
}
