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

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    uint16_t port = 8421;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = static_cast<uint16_t>(std::stoi(argv[2]));

    // Load certificates from ./certs into a CertGraph instance
    namespace fs = std::filesystem;
    pki487::CertGraph certGraph;
    int certs_added = 0;
    if (fs::exists("./certsFiles") && fs::is_directory("./certsFiles")) {
        for (auto &entry : fs::directory_iterator("./certsFiles")) {
            if (!entry.is_regular_file()) continue;
            // read file contents
            std::ifstream in(entry.path(), std::ios::binary);
            if (!in) continue;
            std::ostringstream ss;
            ss << in.rdbuf();
            std::string txt = ss.str();
            // only attempt to parse files that look like Cert487 files
            if (txt.find("-----BEGIN CERT487-----") == std::string::npos) continue;
            auto ec = certGraph.add_cert_from_text(txt);
            if (!ec.has_value()) ++certs_added;
        }
        certGraph.build_edges();
    }
    std::cout << "Loaded " << certs_added << " certificate(s) into CertGraph\n";
    // Note: certGraph is local to main; you can keep it or move it to a wider scope if needed.

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

    // Alice's RSA keys (n,e,d)
    int n = 769864357, e = 142112703, d = 409609311;

    // Send our public key to server: RSA_PUB <n> <e>\n
    std::string publine = "RSA_PUB " + std::to_string(n) + " " + std::to_string(e) + "\n";
    if (!send_all(sock, publine)) { perror("send"); close(sock); return 1; }

    // After exchanging RSA pubkeys, send a CRL file (hex-encoded) if present
    // Use helper make_file_message to build the message from a file path
    try {
        namespace fs = std::filesystem;
        if (fs::exists("./crlFIles") && fs::is_directory("./crlFIles")) {
            for (auto &entry : fs::directory_iterator("./crlFIles")) {
                if (!entry.is_regular_file()) continue;
                std::string msg = make_file_message(entry.path().string(), "CRL");
                if (msg.empty()) continue;
                if (send_all(sock, msg)) {
                    std::cout << "Client: sent CRL file '" << entry.path().filename().string() << "' (message length=" << msg.size() << ") to server\n";
                } else {
                    std::cerr << "Client: failed to send CRL file\n";
                }
                break; // send only one file
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Client: error sending CRL file: " << e.what() << "\n";
    }

    // Receive server's RSA pub: "RSA_PUB <n> <e>\n"
    std::string srv_line = recv_line(sock);
    if (srv_line.rfind("RSA_PUB ", 0) != 0) {
        std::cerr << "Expected RSA_PUB from server, got '" << srv_line << "'\n";
        close(sock);
        return 1;
    }
    unsigned long long server_n_tmp = 0ull;
    uint32_t server_e = 0u;
    {
        std::istringstream iss(srv_line.substr(8));
        iss >> server_n_tmp >> server_e;
    }
    uint32_t server_n = static_cast<uint32_t>(server_n_tmp);
    std::cout << "Client: received server RSA pub n=" << server_n << " e=" << server_e << std::endl;

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
