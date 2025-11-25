#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>
#include "./Helpers/net_utils.hpp"
#include "./Helpers/SDESModes.hpp"
#include "./Helpers/MathUtils.hpp"
#include "./Helpers/FastModExp.hpp"
#include "./Helpers/DiffeHellman.hpp"
#include <bitset>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include "./certs/certParser.hpp"
#include <algorithm>

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    uint16_t port = 8421;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

    pki487::CertGraph certGraph;
    certGraph.add_cert_from_file("./certFiles/Zach.cert487");
    certGraph.add_cert_from_file("./certFiles/Alice.cert487");
    certGraph.add_cert_from_file("./certFiles/Wurth.cert487");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << server_ip << "\n";
        close(sock);
        return 1;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    std::cout << "Connected to " << server_ip << ":" << port << "\n";

    // Load primes and math utilities used later for DH and RSA helpers
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");
    if (primes.size() < 2) {
        std::cerr << "Not enough primes in primes.csv\n";
        close(sock);
        return 1;
    }

    // Alice's RSA keys (n,e,d) - small example values
    int n = 769864357, e = 142112703, d = 409609311;

    pki487::Cert487 bob_cert;

    // send CRL first, wait server ack, then send cert chain (skip any certs revoked)
    try {
        namespace fs = std::filesystem;

        // find first CRL file (optional)
        std::optional<std::string> crl_path;
        if (fs::exists("./crlFIles") && fs::is_directory("./crlFIles")) {
            for (auto &entry : fs::directory_iterator("./crlFIles")) {
                if (!entry.is_regular_file()) continue;
                crl_path = entry.path().string();
                break;
            }
        }

        // helper to parse CRL bytes (assume ASCII list of revoked serial ints separated by whitespace/newline)
        auto parse_crl_bytes = [](const std::vector<unsigned char>& bytes) {
            std::unordered_set<int> revoked;
            std::string s(bytes.begin(), bytes.end());
            std::istringstream iss(s);
            int x;
            while (iss >> x) revoked.insert(x);
            return revoked;
        };

        std::unordered_set<int> local_revoked; // used to avoid sending revoked certs

        if (crl_path.has_value()) {
            // read raw CRL bytes locally so we can parse and avoid sending revoked certs
            std::ifstream ifs(*crl_path, std::ios::binary);
            if (ifs) {
                std::vector<unsigned char> crl_bytes((std::istreambuf_iterator<char>(ifs)),
                                                     std::istreambuf_iterator<char>());
                local_revoked = parse_crl_bytes(crl_bytes);
            }

            // send CRL to server (hex-encoded single-line message) and then send CRL_DONE
            std::string crlmsg = make_file_message(*crl_path, "CRL");
            if (!crlmsg.empty()) {
                if (!send_all(sock, crlmsg)) {
                    std::cerr << "Client: failed to send CRL file to server\n";
                    close(sock);
                    return 1;
                }
                std::cout << "Client: sent CRL '" << std::filesystem::path(*crl_path).filename().string() << "' to server\n";
            }
        }

        // signal end of CRLs
        if (!send_all(sock, std::string("CRL_DONE\n"))) {
            std::cerr << "Client: failed to send CRL_DONE\n";
            close(sock);
            return 1;
        }

        // wait for server CRL acknowledgement
        std::string crl_ack = recv_line(sock);
        if (crl_ack != "CRL_OK") {
            std::cerr << "Client: server rejected CRL or error: '" << crl_ack << "'\n";
            close(sock);
            return 1;
        }
        std::cout << "Client: server accepted CRL\n";

        // Now send the whole chain of certs (all .cert487 files in ./certFiles) to the server,
        // but skip any certificates that are listed in the local CRL.
        try {
            int sent_count = 0;
            if (fs::exists("./certFiles") && fs::is_directory("./certFiles")) {
                for (auto &entry : fs::directory_iterator("./certFiles")) {
                    if (!entry.is_regular_file()) continue;
                    auto p = entry.path();
                    if (p.extension() != ".cert487") continue;
                    // quick check: parse serial from file and skip if revoked
                    bool skip = false;
                    try {
                        auto cert = pki487::Cert487::from_file(p.string());
                        if (local_revoked.find(cert.serial) != local_revoked.end()) {
                            std::cout << "Client: skipping sending revoked cert '" << p.filename().string() << "' (serial=" << cert.serial << ")\n";
                            skip = true;
                        }
                    } catch (...) {
                        // If parsing fails, still attempt to send file (server will validate)
                    }
                    if (skip) continue;

                    std::string certmsg = make_file_message(p.string(), "CERT");
                    if (certmsg.empty()) continue;
                    if (!send_all(sock, certmsg)) {
                        std::cerr << "Client: failed to send certificate '" << p.string() << "'\n";
                        continue;
                    }
                    ++sent_count;
                    std::cout << "Client: sent certificate '" << p.filename().string() << "' to server\n";
                }
            }
            // Signal end of chain
            std::string done = "CERT_DONE\n";
            send_all(sock, done);
            std::cout << "Client: sent CERT_DONE (" << sent_count << " files)\n";
        } catch (const std::exception &ex) {
            std::cerr << "Client: error sending cert chain: " << ex.what() << "\n";
        }

        // receive server's certificate (Bob) after server validates the received chain
        std::string cert_line = recv_line(sock);
        if (!cert_line.empty()) {
            // Expect a CERT <filename> <hex> line containing Bob's cert
            bool saved = parse_and_save_file_message(cert_line, "./received_certs", "CERT");
            if (saved) {
                std::cout << "Client: received and saved server certificate to ./received_certs/\n";
                try {
                    std::string bob_path = "./received_certs/Bob.cert487";
                    if (std::filesystem::exists(bob_path) && std::filesystem::is_regular_file(bob_path)) {
                        bob_cert = pki487::Cert487::from_file(bob_path);
                        certGraph.add_cert_from_file(bob_path);
                        std::cout << "Client: loaded Bob certificate\n";
                    }
                } catch (...) {
                    std::cerr << "Client: failed to parse saved Bob certificate\n";
                }
            } else {
                std::cerr << "Client: failed to save server certificate line\n";
            }
        } else {
            std::cerr << "Client: no certificate line received from server\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "Client: certificate/CRL exchange error: " << e.what() << "\n";
    }

    certGraph.build_edges();

    // Find certification path from Bob -> Alice (if any)
    auto pathRes = certGraph.find_path_by_subjects("Bob", "Alice");
    if (!pathRes.has_value()) {
        std::cerr << "Client: missing certificate(s) for Bob or Alice; stopping chain\n";
        close(sock);
        return 1;
    }
    // value present: empty vector means both endpoints present but no path found
    if (pathRes->first.empty()) {
        std::cerr << "Client: no valid certification path found from 'Bob' to 'Alice'; stopping chain\n";
        // Print available subjects for debugging
        std::cerr << "Client: available certificates:" << std::endl;
        for (const auto &kv : certGraph.nodes()) {
            std::cerr << "  serial=" << kv.first << " subject='" << kv.second.subject << "' issuer='" << kv.second.issuer << "' trust=" << kv.second.cert.trust_level << "\n";
        }
        close(sock);
        return 1;
    }
    // Otherwise we have a valid path; print it
    std::cout << "Client: found certification path (serials):";
    for (int s : pathRes->first) std::cout << " " << s;
    std::cout << "  min_trust=" << pathRes->second << "\n";

    auto server_n = bob_cert.subject_pubkey_pem.n;
    auto server_e = bob_cert.subject_pubkey_pem.exponent;

    // send a seperate key which is randomly generated using signed RSA
    // That is we enrypt with server's public key (n,e) and sign with client's private key (d,n)

    // Generate a random 8-bit key, print it, then encrypt with server's public key
    // and sign with client's private key. We do NOT use this key for anything
    // else — it's just printed/sent as requested.
    {
        // generate random 8-bit value
        std::random_device rd_key;
        std::mt19937 gen_key(rd_key());
        std::uniform_int_distribution<int> dist8(0, 255);
        uint8_t random_key = static_cast<uint8_t>(dist8(gen_key));

        // Print the raw random key (decimal and hex)
        std::ostringstream koss;
        koss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(random_key);
        std::cout << "Client: generated random 8-bit key = " << static_cast<int>(random_key)
                  << " (" << koss.str() << ")" << std::dec << std::setfill(' ') << std::endl;

        // RSA-encrypt the 8-bit key with server's public key: c = key^e mod n
        // and sign the 8-bit key with client's private key: s = key^d mod n
        uint32_t key_val = static_cast<uint32_t>(random_key);
        uint32_t enc_key = 0u;
        uint32_t sig_key = 0u;
        try {
            pki487::keypair server_pub{static_cast<uint32_t>(server_n), static_cast<uint32_t>(server_e)};
            pki487::keypair client_priv{static_cast<uint32_t>(n), static_cast<uint32_t>(d)};
            enc_key = pki487::Rsa::encrypt_uint32(key_val, server_pub);
            sig_key = pki487::Rsa::sign_uint32(key_val, client_priv);
        } catch (const std::exception &ex) {
            std::cerr << "Client: RSA operation failed: " << ex.what() << "\n";
        }

        // Print encrypted and signed numeric values (decimal + hex)
        auto print_u32 = [&](const std::string &label, uint32_t v) {
            std::ostringstream oss;
            oss << "0x" << std::hex << v;
            std::cout << "Client: " << label << " = " << std::dec << v << " (" << oss.str() << ")" << std::endl;
        };
        print_u32("encrypted_key", enc_key);
        print_u32("signed_key", sig_key);

        // Send to server in a simple textual form: KEY <enc_hex> <sig_hex>\n
        auto u32_to_hex = [&](uint32_t v) {
            std::ostringstream oss;
            oss << std::hex << std::setw(8) << std::setfill('0') << v;
            return oss.str();
        };
        std::string keymsg = std::string("KEY ") + u32_to_hex(enc_key) + " " + u32_to_hex(sig_key) + "\n";
        if (!send_all(sock, keymsg)) {
            std::cerr << "Client: failed to send KEY message to server\n";
        } else {
            std::cout << "Client: sent KEY message to server\n";
        }
    }


    // Now send signed Diffie-Hellman params: choose prime p and generator g and our public A
    int dh_p = 0, dh_g = -1;
    for (int attempt = 0; attempt < 10 && dh_g == -1; ++attempt) {
        int cand = mathUtils.pickRandomFrom(primes);
        if (cand <= 3) continue;
        int gen = mathUtils.findGenerator(cand);
        if (gen > 1) {
            dh_p = cand;
            dh_g = gen;
            std::cout << "Client: selected DH parameters p=" << dh_p << " g=" << dh_g << " (candidate attempt=" << attempt << ")\n";
            break;
        }
    }
    if (dh_g == -1) {
        std::cerr << "Client: failed to find DH prime/generator\n";
        close(sock);
        return 1;
    }

    // choose client's DH private
    std::random_device rd2;
    std::mt19937 gen2(rd2());
    std::uniform_int_distribution<int> priv_dist(2, dh_p - 2);
    int client_priv = priv_dist(gen2);
    std::cout << "Client: chosen DH private key (client_priv)=" << client_priv << "\n";
    DiffeHellman dh(dh_p, dh_g);
    int A = dh.calculatePublicKey(client_priv);
    std::cout << "Client: computed DH public A=" << A << "\n";

    // hash p,g,A using S-DES CBC hash (per CBCHash.cpp) and sign with client's RSA private
    auto cbc_hash = [&](uint32_t p, uint32_t g, uint32_t a, uint32_t b = 0u, bool use_b = false) {
        std::bitset<10> hash_key(std::string("1000000000"));
        SDESModes hashSdes(hash_key);
        std::bitset<8> zero_iv(std::string("00000000"));
        std::string data = std::to_string(p) + "," + std::to_string(g) + "," + std::to_string(a);
        if (use_b) data += "," + std::to_string(b);
        std::vector<std::bitset<8>> inputBits;
        for (char c : data) inputBits.emplace_back(static_cast<unsigned long>(static_cast<unsigned char>(c)));
        if (inputBits.empty()) inputBits.emplace_back(static_cast<unsigned long>(0));
        auto hashed = hashSdes.encrypt(inputBits, EncryptionMode::CBC, zero_iv);
        return static_cast<uint32_t>(hashed.back().to_ulong());
    };

    uint32_t hash1 = cbc_hash(static_cast<uint32_t>(dh_p), static_cast<uint32_t>(dh_g), static_cast<uint32_t>(A));
    std::cout << "Client: CBC hash for (p,g,A) = " << hash1 << "\n";
    uint32_t sigA = mathUtils.rsa_sign_uint32(hash1, d, n);
    std::cout << "Client: signed hash sigA=" << sigA << "\n";

    std::string dhinit = "DH_INIT " + std::to_string(dh_p) + " " + std::to_string(dh_g) + " " + std::to_string(A) + " " + std::to_string(sigA) + "\n";
    if (!send_all(sock, dhinit)) { perror("send"); close(sock); return 1; }
    std::cout << "Client: sent DH_INIT p=" << dh_p << " g=" << dh_g << " A=" << A << " sig=" << sigA << std::endl;

    // receive DH_REPLY <B> <sigB>\n
    std::string reply = recv_line(sock);
    if (reply.rfind("DH_REPLY ", 0) != 0) {
        std::cerr << "Client: expected DH_REPLY, got '" << reply << "'\n";
        close(sock);
        return 1;
    }
    uint32_t B = 0u, sigB = 0u;
    {
        std::istringstream iss(reply.substr(9));
        iss >> B >> sigB;
    }
    std::cout << "Client: received DH_REPLY B=" << B << " sigB=" << sigB << "\n";
    // verify server signature over (p,g,A,B) using S-DES CBC hash
    uint32_t hash2 = cbc_hash(static_cast<uint32_t>(dh_p), static_cast<uint32_t>(dh_g), static_cast<uint32_t>(A), B, true);
    std::cout << "Client: CBC hash for (p,g,A,B) = " << hash2 << "\n";
    if (!mathUtils.rsa_verify_uint32(hash2, sigB, server_e, server_n)) {
        std::cerr << "Client: server DH_REPLY signature verification failed\n";
        close(sock);
        return 1;
    }
    std::cout << "Client: verified DH_REPLY signature\n";

    // compute shared secret
    uint32_t shared = static_cast<uint32_t>(dh.calculateSharedSecret(static_cast<int>(B), client_priv));
    std::cout << "Client: computed DH shared secret = " << shared << std::endl;

    // Generate a random 8-bit IV for CBC mode
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    uint8_t iv = static_cast<uint8_t>(dist(gen));
    std::bitset<8> cbc_iv(iv);
    std::cout << "Generated 8-bit IV for CBC: " << cbc_iv << "\n";

    if (!send_all(sock, std::string("IV ") + std::to_string(cbc_iv.to_ulong()) + "\n")) {
        perror("send");
        close(sock);
        return 1;
    }

    // Derive 10-bit SDES key from shared secret (simple: take s mod 1024)
    int s = static_cast<int>(shared);
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    std::cout << "Client: derived 10-bit S-DES key = " << sdes_key << " (" << sdes_key.to_ulong() << ")\n";
    SDESModes sdes(sdes_key);

    // Helper lambdas for hex encoding/decoding
    auto bytes_to_hex = [](const std::vector<unsigned char>& bytes) {
        std::ostringstream oss;
        for (unsigned char b : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    };

    auto hex_to_bytes = [](const std::string &hex) {
        std::vector<unsigned char> out;
        if (hex.size() % 2 != 0) return out;
        for (size_t i = 0; i < hex.size(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            uint32_t byte;
            std::stringstream ss;
            ss << std::hex << byteStr;
            ss >> byte;
            out.push_back(static_cast<unsigned char>(byte));
        }
        return out;
    };

    // Sender loop: read stdin lines, encrypt and send as MSG <hex>\n
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input == "/quit") {
            send_all(sock, std::string("BYE\n"));
            break;
        }
        // Log the keyboard input we're about to send
        std::cout << "Keyboard input: '" << input << "'\n";

        std::vector<std::bitset<8>> plaintext_bits;
        for (char c : input) {
            std::bitset<8> pt(static_cast<unsigned char>(c));
            plaintext_bits.push_back(pt);
        }
        auto cipher_bits = sdes.encrypt(plaintext_bits, EncryptionMode::CBC, cbc_iv);
        // convert bitsets to bytes
        std::vector<unsigned char> cipher_bytes;
        cipher_bytes.reserve(cipher_bits.size());
        for (const auto &b : cipher_bits) cipher_bytes.push_back(static_cast<unsigned char>(b.to_ulong()));
        std::string hex = bytes_to_hex(cipher_bytes);
        // Log the encrypted message we're sending (hex)
        std::cout << "Encrypted (hex) sent: " << hex << std::endl;

        // Update session CBC IV to last ciphertext byte so consecutive messages chain
        if (!cipher_bytes.empty()) {
            uint8_t last_cipher_byte = cipher_bytes.back();
            cbc_iv = std::bitset<8>(last_cipher_byte);
            std::cout << "Client: updated session CBC IV to " << cbc_iv << " (from last ciphertext byte " << (int)last_cipher_byte << ")\n";
        } else {
            std::cout << "Client: cipher_bytes empty, not updating session IV\n";
        }

        std::string out = std::string("MSG ") + hex + "\n";
        if (!send_all(sock, out)) break;
    }

    // Close and exit
    close(sock);
    return 0;
}
