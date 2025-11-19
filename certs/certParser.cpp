#include "certParser.hpp"
#include "io.hpp"
#include "../publicKeys.hpp"
#include "crl487.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <system_error>
#include <climits>
#include <algorithm>
#include <ctime>

namespace pki487 {

// ask chat-gpt for a function to parse and read in a certificate from a file and add to graph
std::optional<std::error_code> CertGraph::add_cert_from_text(const std::string& text) {
    try {
        Cert487 c = Cert487::parse(text);
        // Verify signature using issuer's public key. The issuer's public key may be available
        // from previously added certificates (search _nodes by subject), or from the static
        // known public key map (publicKeys.hpp). If no public key is found or verification
        // fails, reject the certificate and return an error.
        std::vector<unsigned char> sig_bytes = c.signature_bytes();
        std::string tbs = c.serialize_tbs();
        std::optional<pki487::keypair> issuer_pub;
        // Look for an issuer cert already present in the graph
        for (const auto &kv : _nodes) {
            if (kv.second.subject == c.issuer) {
                issuer_pub = kv.second.cert.subject_pubkey_pem;
                break;
            }
        }
        // Fallback to compile-time known public keys
        if (!issuer_pub) {
            auto pk = pki487::lookup_public_key(c.issuer);
            if (pk.has_value()) issuer_pub = pki487::keypair{pk->n, pk->e};
        }
        if (!issuer_pub) {
            std::cerr << "CertGraph::add_cert_from_text: issuer public key for '" << c.issuer << "' not found; rejecting cert serial " << c.serial << "\n";
            return std::make_error_code(std::errc::permission_denied);
        }
        // Verify signature using RSA helper
        if (!pki487::Rsa::verify_message(tbs, *issuer_pub, sig_bytes)) {
            std::cerr << "CertGraph::add_cert_from_text: signature verification failed for cert serial " << c.serial << " (issuer='" << c.issuer << "')\n";
            return std::make_error_code(std::errc::invalid_argument);
        }

        // Check received CRLs (verify CRLs first) to ensure this certificate is not revoked.
        if (is_cert_revoked_by_received_crls(c.serial, "./received_crl")) {
            std::cerr << "CertGraph::add_cert_from_text: certificate serial " << c.serial << " revoked by verified CRL\n";
            return std::make_error_code(std::errc::permission_denied);
        }
        
        CertNode node;
        node.serial = c.serial;
        node.subject = c.subject;
        node.issuer = c.issuer;
        node.cert = std::move(c);
        // Insert/replace node
        _nodes[node.serial] = node;
        // We'll repopulate entire index in build_edges to keep consistent
        return std::nullopt;
    } catch (const std::exception&) {
        return std::make_error_code(std::errc::invalid_argument);
    }
}

// Verify a CRL's signature using issuer public key available from the graph or static known keys.
static bool verify_crl_signature(const std::unordered_map<int, CertNode>& nodes, const pki487::Crl487& crl) {
    // Find issuer public key in nodes
    std::optional<pki487::keypair> issuer_pub;
    for (const auto &kv : nodes) {
        if (kv.second.subject == crl.issuer) {
            issuer_pub = kv.second.cert.subject_pubkey_pem;
            break;
        }
    }
    if (!issuer_pub) {
        auto pk = pki487::lookup_public_key(crl.issuer);
        if (pk.has_value()) issuer_pub = pki487::keypair{pk->n, pk->e};
    }
    if (!issuer_pub) return false;
    auto tbs = crl.serialize_tbs();
    auto sig = crl.signature_bytes();
    return pki487::Rsa::verify_message(tbs, *issuer_pub, sig);
}

bool CertGraph::is_cert_revoked_by_received_crls(int serial, const std::string& crl_dir) const {
    namespace fs = std::filesystem;
    if (!fs::exists(crl_dir) || !fs::is_directory(crl_dir)) return false;
    bool any_verified = false;
    bool revoked_found = false;
    std::time_t now = std::time(nullptr);
    for (auto &entry : fs::directory_iterator(crl_dir)) {
        if (!entry.is_regular_file()) continue;
        // try to read file and parse CRL
        try {
            std::ifstream in(entry.path(), std::ios::binary);
            if (!in) continue;
            std::ostringstream ss;
            ss << in.rdbuf();
            auto txt = ss.str();
            // quick check
            if (txt.find("-----BEGIN CRL487-----") == std::string::npos) continue;
            pki487::Crl487 crl = pki487::Crl487::parse(txt);
            // verify signature and time validity
            if (!verify_crl_signature(_nodes, crl)) continue;
            if (!pki487::crl_time_valid(crl, static_cast<long long>(now))) continue;
            any_verified = true;
            // check if serial is revoked (CRL stores long long)
            if (pki487::crl_is_revoked(crl, static_cast<long long>(serial))) {
                revoked_found = true;
                break;
            }
        } catch (...) {
            continue; // skip bad files
        }
    }
    // If no verified CRLs were found, return false (treat as 'not revoked' by verified CRLs)
    return revoked_found;
}

std::optional<std::error_code> CertGraph::add_cert_from_file(const std::string& filepath) {
    try {
        std::ifstream in(filepath, std::ios::binary);
        if (!in) return std::make_error_code(std::errc::no_such_file_or_directory);
        std::ostringstream ss;
        ss << in.rdbuf();
        std::string txt = ss.str();
        if (txt.find("-----BEGIN CERT487-----") == std::string::npos) {
            return std::make_error_code(std::errc::invalid_argument);
        }
        return add_cert_from_text(txt);
    } catch (...) {
        return std::make_error_code(std::errc::io_error);
    }
}

std::optional<int> CertGraph::add_certs_from_directory(const std::string& dirpath) {
    namespace fs = std::filesystem;
    if (!fs::exists(dirpath) || !fs::is_directory(dirpath)) return std::nullopt;
    int added = 0;
    for (auto &entry : fs::directory_iterator(dirpath)) {
        if (!entry.is_regular_file()) continue;
        auto ec = add_cert_from_file(entry.path().string());
        if (!ec.has_value()) ++added;
    }
    // Build edges after adding all
    build_edges();
    return added;
}

// Created parents and childen relationships between nodes based on subject/issuer matching
void CertGraph::build_edges() {
    // Rebuild subject index
    _subject_index.clear();
    for (const auto& kv : _nodes) {
        const auto& serial = kv.first;
        const auto& n = kv.second;
        _subject_index[n.subject].push_back(serial);
    }

    // Clear children and parents lists
    for (auto &kv : _nodes) { kv.second.children.clear(); kv.second.parents.clear(); }

    // For each certificate (child candidate), find issuer matching subject entries
    for (const auto& kv : _nodes) {
        const auto& child_serial = kv.first;
        const auto& child_node = kv.second;
        auto issuer_name = child_node.issuer;
        auto it = _subject_index.find(issuer_name);
        if (it == _subject_index.end()) continue;
        // For each issuer serial matching that issuer_name, add an edge issuer -> child
        for (auto issuer_serial : it->second) {
            // find issuer node and add child_serial to its children
            auto itnode = _nodes.find(issuer_serial);
            if (itnode != _nodes.end()) {
                itnode->second.children.push_back(child_serial);
                // record reverse link: child -> issuer (parent)
                auto itchild = _nodes.find(child_serial);
                if (itchild != _nodes.end()) itchild->second.parents.push_back(issuer_serial);
            }
        }
    }
}

// Worked with chat-gpt to develop a breadth-first search function
// Depth-first search helper (iterative implementation).
// Return semantics:
//  - std::nullopt => one or both of the start/target serials are not present in `nodes`.
//  - empty vector (value present but size==0) => start and target exist but no path was found.
//  - non-empty vector => a path from start to target (inclusive) represented as a sequence of serials.
//
// We use an explicit stack and a parent map to reconstruct the path when the target is found. This
// avoids deep recursion and makes the search order explicit (LIFO = DFS).
static std::optional<std::vector<int>> dfs_impl(const std::unordered_map<int, CertNode>& nodes,
                                                      int start,
                                                      int target) {
    // Validate presence of endpoints
    if (nodes.find(start) == nodes.end() || nodes.find(target) == nodes.end()) {
        return std::nullopt;
    }

    // Quick path when start == target
    if (start == target) return std::vector<int>{start};

    std::unordered_set<int> visited;
    std::unordered_map<int, int> parent; // child -> parent
    std::vector<int> stack;
    stack.reserve(nodes.size());
    stack.push_back(start);
    visited.insert(start);

    while (!stack.empty()) {
        int cur = stack.back(); stack.pop_back();
        auto it = nodes.find(cur);
        if (it == nodes.end()) continue; // defensive: should not happen

        // Iterate neighbors (children and parents). Using the order as stored; LIFO gives DFS behavior.
        // First visit children (certs this node issued)
        for (int neighbor : it->second.children) {
            if (visited.find(neighbor) != visited.end()) continue;
            visited.insert(neighbor);
            parent[neighbor] = cur;
            if (neighbor == target) {
                // Reconstruct path from start -> ... -> target
                std::vector<int> path;
                int curp = target;
                while (true) {
                    path.push_back(curp);
                    if (curp == start) break;
                    curp = parent[curp];
                }
                std::reverse(path.begin(), path.end());
                return path;
            }
            stack.push_back(neighbor);
        }

        // Then visit parents (issuers of this cert) so we can walk upward as well
        for (int neighbor : it->second.parents) {
            if (visited.find(neighbor) != visited.end()) continue;
            visited.insert(neighbor);
            parent[neighbor] = cur;
            if (neighbor == target) {
                std::vector<int> path;
                int curp = target;
                while (true) {
                    path.push_back(curp);
                    if (curp == start) break;
                    curp = parent[curp];
                }
                std::reverse(path.begin(), path.end());
                return path;
            }
            stack.push_back(neighbor);
        }
    }

    // No path found, but both endpoints exist
    return std::vector<int>{};
}

std::optional<std::pair<std::vector<int>, int>> CertGraph::find_path_by_serial(int start_serial, int target_serial) const {
    auto res = dfs_impl(_nodes, start_serial, target_serial);
    if (!res.has_value()) return std::nullopt; // missing nodes
    // res has a value: could be empty (no path) or non-empty (path found)
    if (res->empty()) return std::make_optional(std::make_pair(std::vector<int>{}, 0));
    // compute minimum trust along the path
    int min_trust = INT_MAX;
    for (int s : *res) {
        auto it = _nodes.find(s);
        if (it != _nodes.end()) min_trust = std::min(min_trust, it->second.cert.trust_level);
    }
    return std::make_optional(std::make_pair(*res, min_trust));
}

std::optional<std::pair<std::vector<int>, int>> CertGraph::find_path_by_subjects(const std::string& start_subject,
                                                                        const std::string& target_subject) const {
    // find serial candidates for start and target
    std::vector<int> starts;
    std::vector<int> targets;
    for (const auto& kv : _nodes) {
        if (kv.second.subject == start_subject) starts.push_back(kv.first);
        if (kv.second.subject == target_subject) targets.push_back(kv.first);
    }
    if (starts.empty() || targets.empty()) return std::nullopt;

    // Try each start serial, and look for paths to any target serial
    for (auto s : starts) {
        for (auto t : targets) {
            auto p = dfs_impl(_nodes, s, t);
            if (p.has_value() && !p->empty()) {
                // compute min trust for this path
                int min_trust = INT_MAX;
                for (int serial : *p) {
                    auto it = _nodes.find(serial);
                    if (it != _nodes.end()) min_trust = std::min(min_trust, it->second.cert.trust_level);
                }
                return std::make_optional(std::make_pair(*p, min_trust));
            }
        }
    }
    return std::make_optional(std::make_pair(std::vector<int>{}, 0)); // no path found (empty path)
}

} // namespace pki487
