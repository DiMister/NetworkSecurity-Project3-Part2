#include "net_utils.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iterator>
#include "../certs/encoding.hpp"

int send_all(int sock, const std::string &msg) {
    int tosend = static_cast<int>(msg.size());
    int sent = 0;
    while (sent < tosend) {
        int s = send(sock, msg.data() + sent, tosend - sent, 0);
        if (s <= 0) return 0;
        sent += s;
    }
    return 1;
}

std::string recv_line(int sock) {
    std::string out;
    char c;
    while (true) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return std::string();
        if (c == '\n') break;
        out.push_back(c);
    }
    return out;
}

std::string make_file_message(const std::string &filepath, const std::string &prefix) {
    try {
        namespace fs = std::filesystem;
        if (!fs::exists(filepath) || !fs::is_regular_file(filepath)) return std::string();
        std::ifstream in(filepath, std::ios::binary);
        if (!in) return std::string();
        std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (bytes.empty()) return std::string();
        std::string hex = pki487::hex_encode(bytes);
        std::string fname = fs::path(filepath).filename().string();
        return prefix + " " + fname + " " + hex + "\n";
    } catch (...) {
        return std::string();
    }
}

bool parse_and_save_file_message(const std::string &line, const std::string &out_dir, const std::string &expected_prefix) {
    try {
        if (line.empty()) return false;
        std::string prefix_check = expected_prefix + " ";
        if (line.rfind(prefix_check, 0) != 0) return false; // prefix doesn't match

        // parse: prefix filename hex
        size_t p1 = line.find(' ');
        if (p1 == std::string::npos) return false;
        size_t p2 = line.find(' ', p1 + 1);
        if (p2 == std::string::npos) return false;
        std::string fname = line.substr(p1 + 1, p2 - (p1 + 1));
        std::string hex = line.substr(p2 + 1);
        if (hex.empty() || fname.empty()) return false;

        auto bytes = pki487::hex_decode(hex);

        std::filesystem::create_directories(out_dir);
        std::string outpath = std::filesystem::path(out_dir) / fname;
        std::ofstream out(outpath, std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        out.close();
        return true;
    } catch (...) {
        return false;
    }
}
