
#pragma once

#include <string>

// Send entire message on socket. Returns true on success.
int send_all(int sock, const std::string &msg);

// Read a line terminated by '\n' (not including '\n'). Returns empty string on error/close.
std::string recv_line(int sock);
