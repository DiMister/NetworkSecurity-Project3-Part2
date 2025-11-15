
#pragma once

#include <string>

// Send entire message on socket. Returns true on success.
int send_all(int sock, const std::string &msg);

// Read a line terminated by '\n' (not including '\n'). Returns empty string on error/close.
std::string recv_line(int sock);

// Create a text message from a file. The message format is:
//   <prefix> <filename> <hex-data>\n
// Returns empty string on error (can't open/read/encode file).
// Example: make_file_message("./crlFIles/Zach.crl487", "CRL")
std::string make_file_message(const std::string &filepath, const std::string &prefix = "CRL");

// Parse a received file-message line of the form:
//   <prefix> <filename> <hex-data>
// If `expected_prefix` doesn't match the line prefix, returns false and does nothing.
// Otherwise decodes the hex-data and writes the bytes to `out_dir/filename`.
// Returns true on success, false on any error.
bool parse_and_save_file_message(const std::string &line, const std::string &out_dir = "./received_crl", const std::string &expected_prefix = "CRL");
