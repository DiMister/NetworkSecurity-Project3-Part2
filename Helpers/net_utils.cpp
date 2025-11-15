#include "net_utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

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
