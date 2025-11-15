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
#include "./Helpers/net_utils.h"
#include "./Helpers/FastModExp.h"
#include "./Helpers/MathUtils.h"
#include "./Helpers/DiffeHellman.h"
#include "./Helpers/SDESModes.h"
#include <bitset>
#include <thread>
#include <sstream>
#include <iomanip>

int main(int argc, char* argv[]) {
    uint16_t port = 8421;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

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

    // Expect client's RSA public key: "RSA_PUB <n> <e>\n"
    std::string line = recv_line(client_sock);
    if (line.rfind("RSA_PUB ", 0) != 0) {
        std::cerr << "Server: expected RSA_PUB, got '" << line << "'\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    unsigned long long client_n_tmp = 0ull;
    uint32_t client_e = 0u;
    {
        std::istringstream iss(line.substr(8));
        iss >> client_n_tmp >> client_e;
    }
    uint32_t client_n = static_cast<uint32_t>(client_n_tmp);
    std::cout << "Server: received client RSA public n=" << client_n << " e=" << client_e << "\n";

    if (client_n == 0u) {
        std::cerr << "Server: invalid client modulus\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    // Generate RSA keypair for server (small primes from CSV)
    MathUtils mathUtils;
    std::vector<int> primes = mathUtils.loadPrimes("./primes.csv");
    if (primes.size() < 2) {
        std::cerr << "Server: not enough primes to generate RSA keys\n";
        close(client_sock);
        close(listen_sock);
        return 1;
    }

    uint32_t p_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    uint32_t q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    while (q_rsa == p_rsa) q_rsa = static_cast<uint32_t>(mathUtils.pickRandomFrom(primes));
    printf("Server: generated RSA primes p=%u q=%u\n", p_rsa, q_rsa);

    unsigned long long n_tmp = static_cast<unsigned long long>(p_rsa) * static_cast<unsigned long long>(q_rsa);
    uint32_t n = static_cast<uint32_t>(n_tmp);
    uint32_t totient = (p_rsa - 1u) * (q_rsa - 1u);
    printf("Server: computed RSA modulus n=%u totient=%u\n", n, totient);

    uint32_t e = mathUtils.findPublicExponent(totient);
    if (e == 0u) {
        e = 65537u;
        if (mathUtils.findGCD(e, totient) != 1u) {
            std::cerr << "Server: Failed to find suitable public exponent\n";
            close(client_sock);
            close(listen_sock);
            return 1;
        }
    }
    printf("Server: selected public exponent e=%u\n", e);

    uint32_t d = mathUtils.extendedEuclidean(e, totient);
    printf("Server: computed private exponent d=%u\n", d);

    // Send server's RSA pub to client
    std::string server_pub = "RSA_PUB " + std::to_string(n) + " " + std::to_string(e) + "\n";
    if (!send_all(client_sock, server_pub)) {
        std::perror("send");
        close(client_sock);
        close(listen_sock);
        return 1;
    }
    std::cout << "Server: sent RSA_PUB " << n << " " << e << "\n";

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
