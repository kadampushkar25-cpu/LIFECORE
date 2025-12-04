// decrypt_log_line.cpp
// Usage: ./decrypt_log_line
// Requires Encryption.h
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <sstream>
#include <regex>
#include "Encryption.h"

namespace fs = std::filesystem;

static std::string read_last_line(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::string line, last;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) last = line;
    }
    f.close();
    return last;
}

int main() {
    try { init_crypto(); } catch (const std::exception &e) { std::cerr<<"libsodium init failed: "<<e.what()<<"\n"; return 1; }

    std::string logpath = "modules/emergency_messenger/logs/sent_messages.log";
    if (!fs::exists(logpath)) { std::cerr << "Log not found: " << logpath << "\n"; return 2; }

    std::string line = read_last_line(logpath);
    if (line.empty()) { std::cerr << "No lines in log\n"; return 3; }

    // decode base64 to binary wrapped_record
    std::vector<unsigned char> wrapped_bin;
    try { wrapped_bin = base64ToBin(line); } catch (const std::exception &e) { std::cerr<<"Line not valid base64: "<<e.what()<<"\n"; return 4; }
    std::string wrapped_str((char*)wrapped_bin.data(), wrapped_bin.size());

    // load salt
    std::string salt_path = "modules/emergency_messenger/keys/user_salt.bin";
    if (!fs::exists(salt_path)) { std::cerr << "Salt file not found: " << salt_path << "\n"; return 5; }
    std::vector<unsigned char> salt = read_binary_file(salt_path);

    std::string pass;
    std::cout << "Enter passphrase to derive master key: ";
    std::getline(std::cin, pass);
    if (pass.empty()) { std::cerr << "Empty passphrase\n"; return 6; }

    std::string masterKey;
    try { masterKey = derive_master_key(pass, salt); } catch (const std::exception &e) { std::cerr<<"KDF failed: "<<e.what()<<"\n"; return 7; }

    // try to load wrapped_logkey
    std::string wrapped_log_path = "modules/emergency_messenger/keys/wrapped_logkey.bin";
    bool have_logkey = false;
    std::string logKey;
    if (fs::exists(wrapped_log_path)) {
        try {
            auto w = read_binary_file(wrapped_log_path);
            std::string wstr((char*)w.data(), w.size());
            logKey = decrypt_aead(wstr, masterKey);
            have_logkey = true;
        } catch (const std::exception &e) {
            std::cerr << "Failed to unwrap logKey with masterKey: " << e.what() << "\n";
            // continue and try decrypting wrapped_str with masterKey as fallback
            have_logkey = false;
        }
    }

    // attempt decrypt of wrapped_str
    std::string record_plain;
    try {
        if (have_logkey) record_plain = decrypt_aead(wrapped_str, logKey);
        else record_plain = decrypt_aead(wrapped_str, masterKey);
    } catch (const std::exception &e) {
        std::cerr << "Failed to decrypt log line: " << e.what() << "\n";
        return 8;
    }

    std::cout << "\nDecrypted log record:\n" << record_plain << "\n\n";

    // extract base64 message inside record_plain: find " : <b64> [Priority:"
    std::smatch m;
    std::regex re(R"(\s:\s([A-Za-z0-9+/=]+)\s*\[Priority:\s*(\d+)\])");
    if (std::regex_search(record_plain, m, re) && m.size() >= 2) {
        std::string b64msg = m[1].str();
        std::string pr = m[2].str();
        std::cout << "Priority: " << pr << "\n";
        // decode message ciphertext
        try {
            auto bin = base64ToBin(b64msg);
            std::string msg_box((char*)bin.data(), bin.size());
            // decrypt with masterKey (messages encrypted with masterKey)
            std::string plaintext = decrypt_aead(msg_box, masterKey);
            std::cout << "Decrypted message plaintext:\n" << plaintext << "\n";
        } catch (const std::exception &e) {
            std::cerr << "Failed to decode/decrypt inner message: " << e.what() << "\n";
        }
    } else {
        std::cerr << "Couldn't find embedded base64 message in record (format unexpected).\n";
    }

    // zero keys
    sodium_memzero((void*)masterKey.data(), masterKey.size());
    if (!logKey.empty()) sodium_memzero((void*)logKey.data(), logKey.size());
    return 0;
}
