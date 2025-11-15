#include "MathUtils.h"
#include <fstream>
#include <string>
#include <cctype>
#include <random>
#include <set>
#include "FastModExp.h"
using namespace std;

vector<int> MathUtils::loadPrimes(const string &path) const {
    vector<int> primes;
    ifstream in(path);
    if (!in) return primes;
    string line;
    while (getline(in, line)) {
        if (line.empty()) continue;
        if (line == "prime" || line == "Prime") continue;
        size_t a = line.find_first_not_of(" \t\r\n");
        size_t b = line.find_last_not_of(" \t\r\n");
        if (a == string::npos) continue;
        string token = line.substr(a, b - a + 1);
        try {
            int v = stoi(token);
            primes.push_back(v);
        } catch (...) {
            // skip invalid lines
        }
    }
    return primes;
}

int MathUtils::pickRandomFrom(const vector<int>& v, int minInclusive, int maxInclusive) const {
    if (v.empty()) return -1;
    // Collect candidates within range
    std::vector<int> candidates;
    candidates.reserve(v.size());
    for (int x : v) {
        if (x >= minInclusive && x <= maxInclusive) candidates.push_back(x);
    }
    if (candidates.empty()) return -1;

    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
    return candidates[dist(gen)];
}

int MathUtils::findGenerator(int p) const {
    for (int candidate = 2; candidate < p; candidate++) {
        if (isGenerator(candidate, p)) {
            return candidate;
        }
    }
    return -1; // No generator found
}

// credit to https://www.geeksforgeeks.org/dsa/euclidean-algorithms-basic-and-extended/ for code
uint32_t MathUtils::findGCD(uint32_t a, uint32_t b) const {
    if (a == 0) return b;
    return findGCD(b % a, a);
}

uint32_t MathUtils::extendedEuclidean(uint32_t publicKey, uint32_t totientN) const {
    int32_t t = 0, newt = 1;
    int32_t r = totientN, newr = publicKey;

    if(findGCD(publicKey, totientN) != 1) throw std::invalid_argument("publicKey and totientN are not coprime");

    while (newr != 0) {
        uint32_t quotient = r / newr;
        tie(t, newt) = make_pair(newt, t - quotient * newt);
        tie(r, newr) = make_pair(newr, r - quotient * newr);
    }

    if (r > 1) throw std::invalid_argument("Not invertible"); // Not invertible
    if (t < 0) t += totientN;
    return static_cast<uint32_t>(t);
}

bool MathUtils::isGenerator(int g, int p) const {
    set<int> seen;
    int current = 1;
    for (int i = 1; i < p; i++) {
        current = (current * g) % p;
        if (seen.count(current)) return false;  // Early cycle
        seen.insert(current);
    }
    return seen.size() == p - 1;
}

/**
 * @brief Finds a suitable public exponent 'e' for RSA, starting from a random odd number.
 * 
 * The public exponent 'e' must satisfy two conditions:
 * 1. 1 < e < totient_n
 * 2. 'e' must be coprime with totient_n (i.e., gcd(e, totient_n) == 1)
 * 
 * This function finds a suitable public exponent 'e' for RSA as an uint32_t
 * .
 * The public exponent 'e' must satisfy:
 * 1. 1 < e < totient_n
 * 2. gcd(e, totient_n) == 1
 *
 * @param totient_n The result of Euler's Totient function, phi(n).
 * @return A valid public exponent 'e', or 0 if no suitable exponent is found.
 */
uint32_t MathUtils::findPublicExponent(uint32_t totient_n) const {
    if (totient_n <= 2) {
        return 0; // No valid 'e' can exist.
    }

    // 1. Set up a high-quality random number generator.
    std::random_device rd;           // Obtains a non-deterministic seed from the OS.
    std::mt19937 generator(rd());    // Standard Mersenne Twister engine seeded with rd().

    // The distribution for 'e' is between 3 and totient_n - 1.
    std::uniform_int_distribution<uint32_t
    > distribution(3, totient_n - 1);

    // 2. Generate a random starting point.
    uint32_t
     start_candidate = distribution(generator);

    // Ensure the starting candidate is odd. If it's even, add 1.
    if ((start_candidate % 2) == 0) {
        start_candidate++;
    }

    // Part 1: Search from the random start up to totient_n.
    for (uint32_t
         e = start_candidate; e < totient_n; e += 2) {
        if (findGCD(e, totient_n) == 1u) {
            return e; // Found a valid exponent.
        }
    }

    // Part 2: If not found, search from the beginning (3) up to our random start.
    for (uint32_t
         e = 3; e < start_candidate; e += 2) {
        if (findGCD(e, totient_n) == 1u) {
            return e; // Found a valid exponent.
        }
    }

    // If no exponent is found after checking the entire range, return 0 as an error code.
    return 0;
}

int MathUtils::pickRandomFrom(const vector<int>& v) const {
    if (v.empty()) return -1;
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, v.size() - 1);
    return v[dist(gen)];
}

// -------------------- RSA sign/verify helpers --------------------
uint32_t MathUtils::rsa_sign_uint32(uint32_t hash32, uint32_t d, uint32_t n) const {
    if (n == 0) return 0;
    uint32_t m = static_cast<uint32_t>(hash32 % n);
    return FastModExp::powmod(m, d, n);
}

bool MathUtils::rsa_verify_uint32(uint32_t hash32, uint32_t sig, uint32_t e, uint32_t n) const {
    if (n == 0) return false;
    uint32_t recovered = FastModExp::powmod(sig, e, n);
    return recovered == static_cast<uint32_t>(hash32 % n);
}