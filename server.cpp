#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <random>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "./Helpers/net_utils.hpp"
#include "./Helpers/FastModExp.hpp"
#include "./Helpers/MathUtils.hpp"
#include "./Helpers/DiffeHellman.hpp"
#include "./Helpers/SDESModes.hpp"
#include "./certs/certParser.hpp"
#include <bitset>
#include <thread>
#include <sstream>
#include <iomanip>
#include <filesystem>

int main(int argc, char* argv[]) {
    uint16_t port = 8421;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    pki487::CertGraph certGraph;
    certGraph.add_cert_from_file("./certFiles/Zach.cert487");
    certGraph.add_cert_from_file("./certFiles/Bob.cert487");
    certGraph.add_cert_from_file("./certFiles/Wurth.cert487");

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == -1) {
        std::perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::perror("setsockopt");
        close(listen_sock);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        close(listen_sock);
        return 1;
    }

    if (listen(listen_sock, 1) < 0) {
        std::perror("listen");
        close(listen_sock);
        return 1;
    }

    std::cout << "Server listening on port " << port << " (accepting 1 client)\n";

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client_sock < 0) {
        std::perror("accept");
        close(listen_sock);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    // Server's RSA keys (n,e,d)
    int n = 836287813, e = 663980159, d = 707411039;

    // After sending RSA pubkey, perform certificate exchange:
    // 1) receive client's certificate (CERT ...) and save it
    // 2) send server's certificate (Bob) back to client
    // 3) receive CRL (CRL ...) and save it
    pki487::Cert487 alice_cert;
    std::string next_line = recv_line(client_sock);
    std::string line;
    if (!next_line.empty()) {
        // Expect client's certificate first
        bool cert_saved = false;
        if (next_line.rfind("CERT ", 0) == 0) {
            cert_saved = parse_and_save_file_message(next_line, "./received_certs", "CERT");
            auto added = certGraph.add_certs_from_directory("./received_certs");
            alice_cert = pki487::Cert487::from_file("./received_certs/Alice.cert487");

            // Attempt to find and verify a path from Alice to the received Bob cert.
            if (added.has_value()) {
                if (*added == 0) {
                    std::cout << "Server: No new certificates were added from server to attempt path verification\n";
                } else {
                    const std::string &subject = alice_cert.subject;
                    auto res = certGraph.find_path_by_subjects(std::string("Bob"), subject);
                    if (!res.has_value()) {
                        std::cout << "Server: Missing nodes for path check (Bob or " << subject << ")\n";
                    } else if (res->first.empty()) {
                        std::cout << "Server: No verified path found from Bob to '" << subject << "'\n";
                    } else {
                        std::cout << "Server: Found path from Bob to '" << subject << "':\n";
                        std::cout << "  Path (serial:subject[trust]): ";
                        for (int s : res->first) {
                            auto itn = certGraph.nodes().find(s);
                            if (itn != certGraph.nodes().end()) {
                                std::cout << s << ":" << itn->second.subject << "[" << itn->second.cert.trust_level << "] ";
                            } else {
                                std::cout << s << " ";
                            }
                        }
                        std::cout << "\n  Minimum trust on this path: " << res->second << "\n";
                    }
                }
            } else {
                std::cout << "No new certificates were added from server to attempt path verification\n";
            }
        }

        // Send server's certificate (Bob) back to the client
        try {
            std::string bob_path = "./certFiles/Bob.cert487";
            if (std::filesystem::exists(bob_path) && std::filesystem::is_regular_file(bob_path)) {
                std::string certmsg = make_file_message(bob_path, "CERT");
                if (!certmsg.empty() && send_all(client_sock, certmsg)) {
                    std::cout << "Server: sent certificate '" << bob_path << "' to client\n";
                } else {
                    std::cerr << "Server: failed to send Bob certificate\n";
                }
            } else {
                std::cerr << "Server: Bob certificate not found at '" << bob_path << "'\n";
            }
        } catch (const std::exception &e) {
            std::cerr << "Server: error sending Bob certificate: " << e.what() << "\n";
        }

        // If we already consumed a line that's not CERT, that might be the CRL or DH_INIT.
        // If we saved a cert, read the next line which should be CRL (optional)
        std::string crlline;
        if (cert_saved) crlline = recv_line(client_sock);
        else if (line.rfind("CRL ", 0) == 0) crlline = line;

        if (!crlline.empty()) {
            bool crl_saved = parse_and_save_file_message(crlline, "./received_crl", "CRL");
            if (crl_saved) {
                std::cout << "Server: CRL saved to ./received_crl/ by helper\n";
                line.clear();
            } else {
                // If it wasn't a CRL, treat it as the next message (e.g., DH_INIT)
                if (crlline.rfind("CRL ", 0) != 0) {
                    line = crlline;
                } else {
                    std::cerr << "Server: received CRL line but failed to save it\n";
                }
            }
        }
    } 
    else {
        // Not a CERT line; keep it for later handling
        line = next_line;
    }


    auto client_n = alice_cert.subject_pubkey_pem.n;
    auto client_e = alice_cert.subject_pubkey_pem.exponent;

    // Now expect signed Diffie-Hellman init from client: "DH_INIT <p> <g> <A> <sig>\n"
    line = recv_line(client_sock);
    if (line.rfind("DH_INIT ", 0) != 0) {
        std::cerr << "Server: expected DH_INIT, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // parse p g A sig
    uint32_t dh_p = 0u, dh_g = 0u, A = 0u, sigA = 0u;
    {
        std::istringstream iss(line.substr(8));
        iss >> dh_p >> dh_g >> A >> sigA;
    }
    std::cout << "Server: received DH_INIT p=" << dh_p << " g=" << dh_g << " A=" << A << " sigA=" << sigA << "\n";
    if (dh_p == 0u || dh_g == 0u) {
        std::cerr << "Server: invalid DH params\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // verify signature from client over (p,g,A) using S-DES CBC hash (same as CBCHash.cpp)
    auto cbc_hash = [&](uint32_t p, uint32_t g, uint32_t a, uint32_t b = 0u, bool use_b = false) {
        // fixed hash key and zero IV (demo only)
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

    MathUtils mathUtils;
    uint32_t hash1 = cbc_hash(dh_p, dh_g, A, 0u, false);
    std::cout << "Server: CBC hash for (p,g,A) = " << hash1 << "\n";
    bool ok = mathUtils.rsa_verify_uint32(hash1, sigA, client_e, client_n);
    if (!ok) {
        std::cerr << "Server: DH_INIT signature verification failed\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    std::cout << "Server: verified DH_INIT signature\n";

    // Choose server DH private and compute B
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist_priv(2, static_cast<int>(dh_p) - 2);
    int server_priv = dist_priv(gen);
    std::cout << "Server: chosen DH private key (server_priv)=" << server_priv << "\n";
    DiffeHellman dh(static_cast<int>(dh_p), static_cast<int>(dh_g));
    int B = dh.calculatePublicKey(server_priv);
    std::cout << "Server: computed DH public B=" << B << "\n";

    // sign hash over (p,g,A,B) using S-DES CBC hash
    uint32_t hash2 = cbc_hash(dh_p, dh_g, A, static_cast<uint32_t>(B), true);
    std::cout << "Server: CBC hash for (p,g,A,B) = " << hash2 << "\n";
    uint32_t sigB = mathUtils.rsa_sign_uint32(hash2, d, n);
    std::cout << "Server: signature sigB=" << sigB << "\n";

    // send DH_REPLY <B> <sigB>
    std::string reply = "DH_REPLY " + std::to_string(B) + " " + std::to_string(sigB) + "\n";
    if (!send_all(client_sock, reply)) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: sent DH_REPLY " << B << " sig=" << sigB << "\n";

    // compute shared secret
    int shared = dh.calculateSharedSecret(A, server_priv);
    std::cout << "Server: computed DH shared secret=" << shared << "\n";

    // Derive a 10-bit SDES key from the shared secret 
    int s = static_cast<int>(shared);
    uint16_t key10 = static_cast<uint16_t>(s % 1024);
    std::bitset<10> sdes_key(key10);
    std::cout << "Server: derived 10-bit S-DES key = " << sdes_key << " (" << sdes_key.to_ulong() << ")\n";
    SDESModes sdes(sdes_key);

    // Helper: hex -> bytes (same format used by client)
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

    // Receive IV
    line = recv_line(client_sock);
    if (line.rfind("IV ", 0) != 0) {
        std::cout << "Server: expected IV, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::bitset<8> cbc_iv(static_cast<uint8_t>(std::stoi(line.substr(3))));
    std::cout << "Received 8-bit IV for CBC: " << cbc_iv << "\n";

    // Wait for BYE or EOF, then cleanup
    while (true) {
        std::string line = recv_line(client_sock);
        if (line.empty()) break;
        if (line.rfind("MSG ", 0) == 0) {
            std::string hex = line.substr(4);
            // Log the encrypted message received (hex)
            std::cout << "Encrypted (hex) received: " << hex << std::endl;

            auto bytes = hex_to_bytes(hex);

            // Convert bytes -> vector<bitset<8>> expected by SDESModes
            std::vector<std::bitset<8>> cipher_bits;
            for (unsigned char b : bytes) cipher_bits.emplace_back(static_cast<unsigned long>(b));

            // Decrypt using current session IV
            auto plain_bits = sdes.decrypt(cipher_bits, EncryptionMode::CBC, cbc_iv);
            std::string plain;
            for (const auto &pt : plain_bits) {
                plain.push_back(static_cast<char>(pt.to_ulong()));
            }
            // Log the decrypted keyboard input
            std::cout << "Decrypted keyboard input: '" << plain << "'" << std::endl;

            // Update session IV to the last ciphertext byte so incoming messages chain
            if (!bytes.empty()) {
                uint8_t last_cipher_byte = bytes.back();
                cbc_iv = std::bitset<8>(last_cipher_byte);
                std::cout << "Server: updated session CBC IV to " << cbc_iv << " (from last ciphertext byte " << (int)last_cipher_byte << ")\n";
            } else {
                std::cout << "Server: received empty ciphertext, not updating session IV\n";
            }
        } else if (line == "BYE") {
            std::cout << "Client closed connection" << std::endl;
            break;
        }
    }

    close(client_sock);
    close(listen_sock);
    return 0;

    
}
