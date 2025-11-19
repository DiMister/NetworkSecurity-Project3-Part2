#pragma once
#include <string>
#include <vector>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <system_error>
#include "cert487.hpp"

namespace pki487 {

// A lightweight node wrapper around a parsed Cert487 used for graph algorithms.
struct CertNode {
	int serial = 0;
	std::string subject;
	std::string issuer;
	Cert487 cert; // full parsed certificate
	std::vector<int> children; // serials of certificates this node issues (issuer -> subject)
	std::vector<int> parents;  // serials of certificates that issued this cert (subject -> issuer)
};

// Graph of certificates with helper methods to build from files and run DFS.
class CertGraph {
public:
	// Parse a certificate file and add it to the graph (replaces existing node with same serial).
	// Returns std::error_code on failure.
	std::optional<std::error_code> add_cert_from_text(const std::string& text);
	// Parse and add a certificate stored in a file. Returns std::nullopt on success,
	// or an error_code describing the failure to read/parse the file.
	std::optional<std::error_code> add_cert_from_file(const std::string& filepath);

	// Scan a directory for certificate files and add them. Returns the number of
	// certificates successfully added, or std::nullopt if the directory doesn't exist
	// or is not readable.
	std::optional<int> add_certs_from_directory(const std::string& dirpath);

	// Build edges between nodes: if nodeA.subject == nodeB.issuer then A -> B
	void build_edges();

	// Find a path (list of serials) from start_serial to target_serial using DFS.
	// Return value semantics:
	//  - std::nullopt => one or both of the start/target serials are not present in the graph.
	//  - value present with .first empty => start/target present but no path found.
	//  - value present with non-empty .first => path found; .second is the minimum trust level among certs on the path.
	std::optional<std::pair<std::vector<int>, int>> find_path_by_serial(int start_serial, int target_serial) const;

	// Convenience: find path by subject names. If multiple certs share a subject name,
	// we attempt DFS from any matching start to any matching target and return the first found path.
	std::optional<std::pair<std::vector<int>, int>> find_path_by_subjects(const std::string& start_subject,
																		  const std::string& target_subject) const;

	// Access to nodes map for inspection
	const std::unordered_map<int, CertNode>& nodes() const { return _nodes; }

	// Check all CRL files in `crl_dir` (default ./received_crl). For each CRL:
	//  - parse the CRL
	//  - verify the CRL signature using the issuer's public key (from received certs or known public keys)
	//  - check CRL validity time
	// Scan verified CRLs in `crl_dir` and return true if any verified CRL lists `serial` as revoked.
	// Returns false if no verified CRL lists the serial (including the case where no CRLs could be verified).
	bool is_cert_revoked_by_received_crls(int serial, const std::string& crl_dir = "./received_crl") const;

private:
	std::unordered_map<int, CertNode> _nodes; // serial -> node
	std::unordered_map<std::string, std::vector<int>> _subject_index; // subject -> serials
	// Read PKI time override from a file. 
	int get_pki_time(const std::string &path = "pki_time.txt") const;
};

}

