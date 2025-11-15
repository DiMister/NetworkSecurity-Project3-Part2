#pragma once
#include <string>
#include <vector>
#include <optional>
#include "Rsa.hpp"

#include <bitset>



namespace pki487 {

struct Cert487 {
    int version = 1;                 // fixed to 1
    std::string signature_algo = "S-DES-CBC-8";
    int serial = 0;            // integer serial
    std::string issuer;              // issuer name
    std::string subject;             // subject name
    long long not_before = 0;        // integer time
    long long not_after = 0;         // integer time
    int trust_level = 0;             // 0..7
    keypair subject_pubkey_pem;  // PEM block

    // signature as sequence of 8-bit blocks (on-disk we store hex of raw bytes)
    std::vector<std::bitset<8>> signature;

    // Return raw bytes of signature (each bitset -> one byte)
    std::vector<unsigned char> signature_bytes() const;

    // Serialize the TBS (to-be-signed) section in canonical order with normalized newlines.
    std::string serialize_tbs() const;

    // Serialize entire cert (with signature).
    std::string serialize_full() const;

    // Parse from full text (throws on error), fills object and returns TBS canonical string as parsed.
    static Cert487 parse(const std::string& text);
};

// Return true if time t is within validity window [not_before, not_after].
bool cert_is_time_valid(const Cert487& c, long long t);

} // namespace pki487
