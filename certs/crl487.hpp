#pragma once
#include <string>
#include <vector>
#include <bitset>

namespace pki487 {

struct Crl487 {
    int version = 1;                  // fixed to 1
    std::string signature_algo = "S-DES-CBC-8";
    std::string issuer;               // issuer name
    long long this_update = 0;        // integer time
    long long next_update = 0;        // integer time
    std::vector<long long> revoked_serials; // list of revoked cert serials

    // signature stored as sequence of 8-bit blocks; on-disk stored as hex of raw bytes
    std::vector<std::bitset<8>> signature;

    // Return raw bytes of signature (each bitset -> one byte)
    std::vector<unsigned char> signature_bytes() const;

    std::string serialize_tbs() const;
    std::string serialize_full() const;
    static Crl487 parse(const std::string& text);
};

// Return true if PKI time is within [this_update, next_update]
bool crl_time_valid(const Crl487& crl, long long t);

// Return true if serial is in revoked list
bool crl_is_revoked(const Crl487& crl, long long serial);

} // namespace pki487
