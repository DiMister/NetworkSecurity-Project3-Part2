#pragma once
#include <cstdint>

class FastModExp {
public:
    // Multiply a * b mod m safely (avoids overflow when possible)
    static uint32_t mul_mod(uint32_t a, uint32_t b, uint32_t mod);

    // Compute base^exp mod mod using fast binary exponentiation
    static uint32_t powmod(uint32_t base, uint32_t exp, uint32_t mod);
};
