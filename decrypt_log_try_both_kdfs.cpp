// decrypt_log_try_both_kdfs.cpp
// Tries Argon2 (derive_master_key) and the old simple KDF (crypto_generichash)
// to decrypt the inner message inside the last encrypted log record.
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <sstream>
#include <regex>
#include "Encryption.h"

namespace fs = std::filesystem;

// old simple KDF (keeps compatibility with earlier builds)
static std::string deriveKeyFromPassword_simple(const std::string &passphrase) {
    // produce 32-byte key using crypto_generichash (BLAKE2b)
    std::string key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, '\0');
    crypto_generichash((unsigned char*)key.data(), key.size(),
                       (const unsigned char*)passphrase.data(), passphrase.size(),
                       NULL, 0);
    return key;
}

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

    std::vector<unsigned char> wrapped_bin;
    try { wrapped_bin = base64ToBin(line); } catch (const std::exception &e) { std::cerr<<"Line not valid base64: "<<e.what()<<"\n"; return 4; }
    std::string wrapped_str((char*)wrapped_bin.data(), wrapped_bin.size());

    std::string salt_path = "modules/emergency_messenger/keys/user_salt.bin";
    if (!fs::exists(salt_path)) { std::cerr << "Salt file not found: " << salt_path << "\n"; return 5; }
    std::vector<unsigned char> salt = read_binary_file(salt_path);

    std::string pass;
    std::cout << "Enter passphrase to derive keys: ";
    std::getline(std::cin, pass);
    if (pass.empty()) { std::cerr << "Empty passphrase\n"; return 6; }

    // derive Argon2 masterKey
    std::string argonKey;
    try { argonKey = derive_master_key(pass, salt); } catch (const std::exception &e) { std::cerr<<"Argon2 KDF failed: "<<e.what()<<"\n"; }

    // derive simple key
    std::string simpleKey;
    try { simpleKey = deriveKeyFromPassword_simple(pass); } catch (...) {}

    // try unwrap wrapped_logkey.bin if present (use argonKey)
    std::string wrapped_log_path = "modules/emergency_messenger/keys/wrapped_logkey.bin";
    std::string logKey;
    bool have_logkey = false;
    if (fs::exists(wrapped_log_path)) {
        try {
            auto w = read_binary_file(wrapped_log_path);
            std::string wstr((char*)w.data(), w.size());
            if (!argonKey.empty()) {
                logKey = decrypt_aead(wstr, argonKey);
                have_logkey = true;
                std::cout << "Unwrapped logKey using Argon2-derived masterKey.\n";
            } else {
                std::cerr << "Argon2 key not available; cannot unwrap logKey.\n";
            }
        } catch (const std::exception &e) {
            std::cerr << "Failed to unwrap logKey: " << e.what() << "\n";
            have_logkey = false;
        }
    } else {
        std::cout << "No wrapped_logkey.bin found; attempting to decrypt record with masterKey(s).\n";
    }

    // decrypt outer wrapped record using logKey (if available) or try both master keys
    std::string record_plain;
    bool outer_ok = false;
    if (have_logkey) {
        try { record_plain = decrypt_aead(wrapped_str, logKey); outer_ok = true; }
        catch (const std::exception &e) { std::cerr << "Failed to decrypt outer record with logKey: " << e.what() << "\n"; }
    }

    // if outer not decrypted yet, try decrypting with argonKey then simpleKey as fallback
    if (!outer_ok && !argonKey.empty()) {
        try { record_plain = decrypt_aead(wrapped_str, argonKey); outer_ok = true; std::cout<<"Decrypted outer record with Argon2-derived key (unwrapped logKey absent).\n"; }
        catch (...) {}
    }
    if (!outer_ok && !simpleKey.empty()) {
        try { record_plain = decrypt_aead(wrapped_str, simpleKey); outer_ok = true; std::cout<<"Decrypted outer record with simple KDF key.\n"; }
        catch (...) {}
    }
    if (!outer_ok) { std::cerr << "Failed to decrypt outer log record with any available key.\n"; return 7; }

    std::cout << "\nDecrypted log record:\n" << record_plain << "\n\n";

    // extract base64 message inside record_plain
    std::smatch m;
    std::regex re(R"(\s:\s([A-Za-z0-9+/=]+)\s*\[Priority:\s*(\d+)\])");
    if (!std::regex_search(record_plain, m, re) || m.size() < 2) {
        std::cerr << "Couldn't find embedded base64 message in record (format unexpected).\n";
        return 8;
    }
    std::string b64msg = m[1].str();
    std::string pr = m[2].str();
    std::cout << "Priority: " << pr << "\n";

    // attempt to decode and decrypt inner message with both candidate keys:
    std::vector<std::pair<std::string,std::string>> attempts; // (key_label, key)
    if (!argonKey.empty()) attempts.emplace_back("Argon2-masterKey", argonKey);
    if (!simpleKey.empty()) attempts.emplace_back("Simple-KDF", simpleKey);

    // also try masterKey = logKey? (unlikely) but skip.

    auto bin = base64ToBin(b64msg);
    std::string msg_box((char*)bin.data(), bin.size());

    bool inner_ok = false;
    for (auto &kp : attempts) {
        try {
            std::string recovered = decrypt_aead(msg_box, kp.second);
            std::cout << "Successfully decrypted inner message with: " << kp.first << "\n";
            std::cout << "Plaintext:\n" << recovered << "\n";
            inner_ok = true;
            break;
        } catch (const std::exception &e) {
            std::cerr << "Attempt with " << kp.first << " failed: " << e.what() << "\n";
        }
    }

    if (!inner_ok) {
        std::cerr << "All decryption attempts failed. Possible reasons:\n"
                  << "- passphrase different from one used when message was created\n"
                  << "- message was encrypted with another key or KDF\n"
                  << "- message ciphertext is corrupt\n";
    }

    // zero sensitive memory
    if (!argonKey.empty()) sodium_memzero((void*)argonKey.data(), argonKey.size());
    if (!simpleKey.empty()) sodium_memzero((void*)simpleKey.data(), simpleKey.size());
    if (!logKey.empty()) sodium_memzero((void*)logKey.data(), logKey.size());

    return inner_ok ? 0 : 9;
}
