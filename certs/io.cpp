#include "io.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

namespace pki487 {

std::string read_text_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("Cannot open file: " + path);
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

void write_text_file(const std::string& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) throw std::runtime_error("Cannot write file: " + path);
    ofs << content;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

std::vector<std::string> split(const std::string& s, char delim, bool allow_empty) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            if (allow_empty || !cur.empty()) out.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if (allow_empty || !cur.empty()) out.push_back(cur);
    return out;
}

std::string canonicalize_newlines(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '\r') {
            // skip, we'll normalize with \n when next char is \n
            continue;
        }
        out.push_back(c);
    }
    // Also strip trailing spaces/tabs on each line
    std::string norm;
    norm.reserve(out.size());
    size_t line_start = 0;
    for (size_t i = 0; i <= out.size(); ++i) {
        if (i == out.size() || out[i] == '\n') {
            size_t line_end = i;
            while (line_end > line_start && (out[line_end-1] == ' ' || out[line_end-1] == '\t')) --line_end;
            norm.append(out.substr(line_start, line_end - line_start));
            if (i != out.size()) norm.push_back('\n');
            line_start = i + 1;
        }
    }
    return norm;
}

void ensure_dir(const std::string& path) {
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

} // namespace pki487
