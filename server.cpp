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
#include <fstream>
#include <filesystem>

int main(int argc, char* argv[]) {
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

    uint16_t port = 8421;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    pki487::CertGraph certGraph;

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

    if (::bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
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

    // Ensure received_certs and received_crl dirs exist
    try {
        std::filesystem::create_directories("./received_certs");
        std::filesystem::create_directories("./received_crl");
    } catch (...) {}

    // first receive CRL(s) from client, ack back
    while (true) {
        std::string in = recv_line(client_sock);
        if (in.empty()) {
            std::cerr << "Server: connection closed while waiting for CRL\n";
            close(client_sock);
            close(listen_sock);
            return 1;
        }
        if (in == "CRL_DONE") {
            break;
        }
        if (in.rfind("CRL ", 0) == 0) {
            // parse "CRL <filename> <hexdata>"
            std::istringstream iss(in);
            std::string tag, filename, hexdata;
            iss >> tag >> filename >> hexdata;
            if (filename.empty() || hexdata.empty()) {
                std::cerr << "Server: malformed CRL line\n";
                continue;
            }
            // decode hex -> bytes
            std::vector<unsigned char> bytes;
            bytes = hex_to_bytes(hexdata);

            // save raw CRL file
            try {
                std::filesystem::path outp = std::filesystem::path("./received_crl") / filename;
                std::ofstream ofs(outp, std::ios::binary);
                ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                ofs.close();
                std::cout << "Server: saved CRL to '" << outp.string() << "' (bytes=" << bytes.size() << ")\n";
            } catch (const std::exception &ex) {
                std::cerr << "Server: failed to save CRL file: " << ex.what() << "\n";
            }
            continue;
        }
        // unexpected non-CRL line -> protocol error
        std::cerr << "Server: expected CRL or CRL_DONE, got: '" << in << "'\n";
        // for robustness, continue reading until CRL_DONE or close
    }

    // send CRL ack 
    if (!send_all(client_sock, std::string("CRL_OK\n"))) {
        std::cerr << "Server: failed to send CRL_OK\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // After CRL ack, expect certificate chain from client: multiple "CERT <file> <hex>\n" then "CERT_DONE\n"
    bool got_any_cert = false;
    while (true) {
        std::string in = recv_line(client_sock);
        if (in.empty()) {
            // connection closed or error
            break;
        }
        if (in == "CERT_DONE") {
            // end of chain
            break;
        }
        if (in.rfind("CERT ", 0) == 0) {
            bool saved = parse_and_save_file_message(in, "./received_certs", "CERT");
            if (saved) got_any_cert = true;
            // continue reading next cert
            continue;
        }
        // Not a CERT line: treat as next protocol message
        // store and break out (unlikely at this stage)
        break;
    }

    // Build parse tree (graph) only from the received certs
    auto added = certGraph.add_certs_from_directory("./received_certs");
    certGraph.build_edges();

    // Find certification path from Bob -> Alice (if any)
    auto pathRes = certGraph.find_path_by_subjects("Bob", "Alice");
    if (!pathRes.has_value()) {
        std::cerr << "Server: missing certificate(s) for Bob or Alice; stopping chain\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    // value present: empty vector means both endpoints present but no path found
    if (pathRes->first.empty()) {
        std::cerr << "Server: no valid certification path found from 'Bob' to 'Alice'; stopping chain\n";
        // Print available subjects for debugging
        std::cerr << "Server: available certificates:" << std::endl;
        for (const auto &kv : certGraph.nodes()) {
            std::cerr << "  serial=" << kv.first << " subject='" << kv.second.subject << "' issuer='" << kv.second.issuer << "' trust=" << kv.second.cert.trust_level << "\n";
        }
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    // Otherwise we have a valid path; print it
    std::cout << "Server: found certification path (serials):";
    for (int s : pathRes->first) std::cout << " " << s;
    std::cout << "  min_trust=" << pathRes->second << "\n";

    // If chain OK, send Bob's certificate back to the client
    try {
        std::string bob_path = "./certFiles/Bob.cert487";
        if (std::filesystem::exists(bob_path) && std::filesystem::is_regular_file(bob_path)) {
            std::string certmsg = make_file_message(bob_path, "CERT");
            if (!certmsg.empty() && send_all(client_sock, certmsg)) {
                std::cout << "Server: sent Bob certificate to client\n";
            } else {
                std::cerr << "Server: failed to send Bob certificate\n";
            }
        } else {
            std::cerr << "Server: Bob certificate not found at '" << bob_path << "'\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "Server: error sending Bob certificate: " << e.what() << "\n";
    }

    // Try to locate Alice's cert among the received files/graph so we can get client's pubkey
    pki487::Cert487 alice_cert;
    try {
        std::string alice_path = "./received_certs/Alice.cert487";
        if (std::filesystem::exists(alice_path) && std::filesystem::is_regular_file(alice_path)) {
            alice_cert = pki487::Cert487::from_file(alice_path);
        }
    } catch (...) { 
        std::cerr << "Server: failed to load Alice certificate from received certs\n";
    }

    auto client_n = alice_cert.subject_pubkey_pem.n;
    auto client_e = alice_cert.subject_pubkey_pem.exponent;

    // Send server's certificate (Bob) back to the client after we've processed the received chain.
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

    // Before DH_INIT we may receive a KEY message; read lines until DH_INIT
    std::string line;
    line = recv_line(client_sock);
    if (line.rfind("KEY ", 0) == 0) {
        // parse KEY <enc_hex> <sig_hex>
        std::istringstream iss(line);
        std::string tag, hexenc, hexsig;
        iss >> tag >> hexenc >> hexsig;
        if (hexenc.empty() || hexsig.empty()) {
            std::cerr << "Server: malformed KEY line\n";
            continue;
        }
        try {
            uint32_t enc_val = static_cast<uint32_t>(std::stoul(hexenc, nullptr, 16));
            uint32_t sig_val = static_cast<uint32_t>(std::stoul(hexsig, nullptr, 16));

            pki487::keypair server_priv{static_cast<uint32_t>(n), static_cast<uint32_t>(d)};
            uint32_t recovered_key = pki487::Rsa::decrypt_uint32(enc_val, server_priv);
            std::cout << "Server: received KEY message, decrypted value=" << recovered_key << "\n";

            // verify signature using client's public key (if available)
            pki487::keypair client_pub{static_cast<uint32_t>(client_n), static_cast<uint32_t>(client_e)};
            bool sig_ok = false;
            try {
                sig_ok = pki487::Rsa::verify_uint32(recovered_key, sig_val, client_pub);
            } catch (...) { sig_ok = false; }
            std::cout << "Server: KEY signature verification=" << (sig_ok ? "OK" : "FAILED") << "\n";
        } catch (const std::exception &ex) {
            std::cerr << "Server: error parsing KEY hex: " << ex.what() << "\n";
        }
    } else {
        printf("Server: expected KEY, got '%s'\n", line.c_str());
    }   
    
    // Now expect signed Diffie-Hellman init from client: "DH_INIT <p> <g> <A> <sig>\n"
    std::string line = recv_line(client_sock);
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
