#include "crl487.hpp"
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

std::string Crl487::serialize_tbs() const {
    std::ostringstream ss;
    ss << "-----BEGIN CRL487-----\n";
    ss << field("VERSION", std::to_string(version));
    ss << field("SIGNATURE-ALGO", signature_algo);
    ss << field("ISSUER", issuer);
    ss << field("THIS-UPDATE", std::to_string(this_update));
    ss << field("NEXT-UPDATE", std::to_string(next_update));
    // revoked serials as comma-separated list
    std::ostringstream rs;
    for (size_t i = 0; i < revoked_serials.size(); ++i) {
        if (i) rs << ",";
        rs << revoked_serials[i];
    }
    ss << field("REVOKED-SERIALS", rs.str());
    ss << "-----END TBS-----\n";
    return canonicalize_newlines(ss.str());
}

std::string Crl487::serialize_full() const {
    std::ostringstream ss;
    ss << serialize_tbs();
    ss << field("SIGNATURE", hex_encode(signature_bytes()));
    ss << "-----END CRL487-----\n";
    return ss.str();
}

Crl487 Crl487::parse(const std::string& text) {
    Crl487 c;
    auto canon = canonicalize_newlines(text);
    auto begin = canon.find("-----BEGIN CRL487-----\n");
    if (begin == std::string::npos) throw std::runtime_error("Missing BEGIN CRL487");
    auto tbs_end = canon.find("-----END TBS-----\n", begin);
    if (tbs_end == std::string::npos) throw std::runtime_error("Missing END TBS");
    std::string tbs = canon.substr(begin, tbs_end - begin + std::string("-----END TBS-----\n").size());

    auto sig_pos = canon.find("SIGNATURE:", tbs_end);
    if (sig_pos == std::string::npos) throw std::runtime_error("Missing SIGNATURE field");
    auto sig_end_line = canon.find('\n', sig_pos);
    std::string sig_line = canon.substr(sig_pos, sig_end_line - sig_pos);
    auto colon = sig_line.find(':');
    if (colon == std::string::npos) throw std::runtime_error("Bad SIGNATURE line");
    {
        std::string tmp = sig_line.substr(colon+1);
        size_t p = 0; while (p < tmp.size() && (tmp[p] == ' ' || tmp[p] == '\t')) ++p;
        tmp = tmp.substr(p);
    auto sig_bytes = hex_decode(trim(tmp));
        c.signature.clear();
        c.signature.reserve(sig_bytes.size());
        for (unsigned char b : sig_bytes) c.signature.emplace_back(std::bitset<8>(b));
    }

    auto end = canon.find("-----END CRL487-----\n", sig_end_line);
    if (end == std::string::npos) throw std::runtime_error("Missing END CRL487");

    auto rest = tbs;
    auto get_value = [&](const std::string& key) -> std::string {
        auto pos = rest.find(key + ": ");
        if (pos == std::string::npos) throw std::runtime_error("Missing field: " + key);
        auto line_end = rest.find('\n', pos);
        if (line_end == std::string::npos) throw std::runtime_error("Malformed field: " + key);
        auto val = rest.substr(pos + key.size() + 2, line_end - (pos + key.size() + 2));
        return val;
    };

    c.version = std::stoi(get_value("VERSION"));
    c.signature_algo = get_value("SIGNATURE-ALGO");
    c.issuer = get_value("ISSUER");
    c.this_update = std::stoll(get_value("THIS-UPDATE"));
    c.next_update = std::stoll(get_value("NEXT-UPDATE"));
    auto rs = get_value("REVOKED-SERIALS");
    c.revoked_serials.clear();
    for (auto& s : split(rs, ',', false)) {
        auto t = trim(s);
        if (!t.empty()) c.revoked_serials.push_back(std::stoll(t));
    }

    return c;
}

bool crl_time_valid(const Crl487& crl, long long t) {
    return t >= crl.this_update && t <= crl.next_update;
}

bool crl_is_revoked(const Crl487& crl, long long serial) {
    return std::find(crl.revoked_serials.begin(), crl.revoked_serials.end(), serial) != crl.revoked_serials.end();
}

std::vector<unsigned char> Crl487::signature_bytes() const {
    std::vector<unsigned char> out;
    out.reserve(signature.size());
    for (const auto &bs : signature) out.push_back(static_cast<unsigned char>(bs.to_ulong()));
    return out;
}

} // namespace pki487
