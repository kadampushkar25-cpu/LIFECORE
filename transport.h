// transport.h
#ifndef TRANSPORT_H
#define TRANSPORT_H
#include <string>
bool send_ciphertext_http(const std::string &url, const std::string &message_b64, int priority, std::string &err);
#endif
