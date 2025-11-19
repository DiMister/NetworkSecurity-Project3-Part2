#include "cert487.hpp"
#include "io.hpp"
#include "encoding.hpp" // hex helpers
#include <bitset>

#include <sstream>
#include <stdexcept>
#include <algorithm>

namespace pki487 {

static std::string field(const std::string& k, const std::string& v) {
    return k + ": " + v + "\n";
}

//asked chat-gpt to create a format for cert files, then added missing fields
std::string Cert487::serialize_tbs() const {
    std::ostringstream ss;
    ss << "-----BEGIN CERT487-----\n";
    ss << field("VERSION", std::to_string(version));
    ss << field("SERIAL", std::to_string(serial));
    ss << field("SIGNATURE-ALGO", signature_algo);
    ss << field("ISSUER", issuer);
    ss << field("SUBJECT", subject);
    ss << field("NOT-BEFORE", std::to_string(not_before));
    ss << field("NOT-AFTER", std::to_string(not_after));
    ss << field("TRUST-LEVEL", std::to_string(trust_level));
    // Serialize the subject public key (numeric keypair) in a small block
    ss << "SUBJECT-PUBKEY: BEGIN\n";
    ss << field("N", std::to_string(subject_pubkey_pem.n));
    ss << field("EXPONENT", std::to_string(subject_pubkey_pem.exponent));
    ss << "SUBJECT-PUBKEY: END\n";
    ss << "-----END TBS-----\n";
    return canonicalize_newlines(ss.str());
}

std::string Cert487::serialize_full() const {
    std::ostringstream ss;
    ss << serialize_tbs();
    // Encode signature bytes as hex for on-disk representation
    auto sig_bytes = signature_bytes();
    ss << field("SIGNATURE", hex_encode(sig_bytes));
    ss << "-----END CERT487-----\n";
    return ss.str();
}

// asked chat-gpt to parse a certificate from text
Cert487 Cert487::parse(const std::string& text) {
    Cert487 c;
    auto canon = canonicalize_newlines(text);
    // Extract TBS block
    auto begin = canon.find("-----BEGIN CERT487-----\n");
    if (begin == std::string::npos) throw std::runtime_error("Missing BEGIN CERT487");
    auto tbs_end = canon.find("-----END TBS-----\n", begin);
    if (tbs_end == std::string::npos) throw std::runtime_error("Missing END TBS");
    std::string tbs = canon.substr(begin, tbs_end - begin + std::string("-----END TBS-----\n").size());

    // After TBS, expect SIGNATURE and END CERT487
    auto sig_pos = canon.find("SIGNATURE:", tbs_end);
    if (sig_pos == std::string::npos) throw std::runtime_error("Missing SIGNATURE field");
    auto sig_end_line = canon.find('\n', sig_pos);
    std::string sig_line = canon.substr(sig_pos, sig_end_line - sig_pos);
    auto colon = sig_line.find(':');
    if (colon == std::string::npos) throw std::runtime_error("Bad SIGNATURE line");
    // Extract value after ':' and possible space
    {
        std::string tmp = sig_line.substr(colon+1);
        // trim leading spaces
        size_t p = 0; while (p < tmp.size() && (tmp[p] == ' ' || tmp[p] == '\t')) ++p;
        tmp = tmp.substr(p);
    // tmp now contains hex string of signature bytes
    auto sig_bytes = hex_decode(trim(tmp));
        c.signature.clear();
        c.signature.reserve(sig_bytes.size());
        for (unsigned char b : sig_bytes) c.signature.emplace_back(std::bitset<8>(b));
    }

    auto cert_end = canon.find("-----END CERT487-----\n", sig_end_line);
    if (cert_end == std::string::npos) throw std::runtime_error("Missing END CERT487");

    // Parse fields inside TBS
    auto rest = tbs;
    auto get_value = [&](const std::string& key) -> std::string {
        auto pos = rest.find(key + ": ");
        if (pos == std::string::npos) throw std::runtime_error("Missing field: " + key);
        auto line_end = rest.find('\n', pos);
        if (line_end == std::string::npos) throw std::runtime_error("Malformed field: " + key);
        auto val = rest.substr(pos + key.size() + 2, line_end - (pos + key.size() + 2));
        return val;
    };

    auto s_version = get_value("VERSION");
    auto s_serial = get_value("SERIAL");
    auto s_sigalg = get_value("SIGNATURE-ALGO");
    c.version = std::stoi(s_version);
    c.serial = std::stoi(s_serial);
    c.signature_algo = s_sigalg;
    c.issuer = get_value("ISSUER");
    c.subject = get_value("SUBJECT");
    c.not_before = std::stoll(get_value("NOT-BEFORE"));
    c.not_after = std::stoll(get_value("NOT-AFTER"));
    c.trust_level = std::stoi(get_value("TRUST-LEVEL"));

    // Subject public key block between markers (numeric keypair)
    auto pem_begin_key = std::string("SUBJECT-PUBKEY: BEGIN\n");
    auto pem_end_key = std::string("SUBJECT-PUBKEY: END\n");
    auto pb = rest.find(pem_begin_key);
    if (pb == std::string::npos) throw std::runtime_error("Missing SUBJECT-PUBKEY: BEGIN");
    pb += pem_begin_key.size();
    auto pe = rest.find(pem_end_key, pb);
    if (pe == std::string::npos) throw std::runtime_error("Missing SUBJECT-PUBKEY: END");
    // Parse the two fields N and EXPONENT inside the block
    {
        std::string keyblock = rest.substr(pb, pe - pb);
        auto get_kv = [&](const std::string& key)->std::string {
            auto pos = keyblock.find(key + ": ");
            if (pos == std::string::npos) throw std::runtime_error("Missing key field: " + key);
            auto line_end = keyblock.find('\n', pos);
            if (line_end == std::string::npos) line_end = keyblock.size();
            return keyblock.substr(pos + key.size() + 2, line_end - (pos + key.size() + 2));
        };
        auto s_n = get_kv("N");
        auto s_exp = get_kv("EXPONENT");
        c.subject_pubkey_pem.n = static_cast<uint32_t>(std::stoul(s_n));
        c.subject_pubkey_pem.exponent = static_cast<uint32_t>(std::stoul(s_exp));
    }

    // Validate trust level range
    if (c.trust_level < 0 || c.trust_level > 7) throw std::runtime_error("TRUST-LEVEL out of range (0..7)");

    return c;
}

Cert487 Cert487::from_file(const std::string& path) {
    auto txt = read_text_file(path);
    return Cert487::parse(txt);
}

bool cert_is_time_valid(const Cert487& c, long long t) {
    return t >= c.not_before && t <= c.not_after;
}

std::vector<unsigned char> Cert487::signature_bytes() const {
    std::vector<unsigned char> out;
    out.reserve(signature.size());
    for (const auto &bs : signature) {
        out.push_back(static_cast<unsigned char>(bs.to_ulong()));
    }
    return out;
}

} // namespace pki487
