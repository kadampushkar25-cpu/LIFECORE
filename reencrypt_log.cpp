// reencrypt_log.cpp
// Usage: ./reencrypt_log modules/emergency_messenger/logs/sent_messages.log
// Requires Encryption.h (Argon2 + AEAD helpers)

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <ctime>
#include <filesystem>
#include <sstream>

#include "Encryption.h"

namespace fs = std::filesystem;

static bool is_timestamp_line(const std::string &line) {
    static std::regex re(R"(^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$)");
    return std::regex_match(line, re);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path-to-sent_messages.log>\n";
        return 2;
    }
    std::string path = argv[1];

    try { init_crypto(); } catch (const std::exception &e) {
        std::cerr << "libsodium init failed: " << e.what() << "\n";
        return 3;
    }

    // find salt file
    std::string salt_path = "modules/emergency_messenger/keys/user_salt.bin";
    if (!fs::exists(salt_path)) {
        std::cerr << "Salt file not found: " << salt_path << "\n";
        std::cerr << "Run ./messenger once to generate the salt file, or place the salt at that path.\n";
        return 4;
    }

    // read salt
    std::vector<unsigned char> salt;
    try { salt = read_binary_file(salt_path); } catch (const std::exception &e) {
        std::cerr << "Failed to read salt: " << e.what() << "\n"; return 5;
    }

    // ask passphrase
    std::string pass;
    std::cout << "Enter passphrase to derive master key for re-encrypting log: ";
    std::getline(std::cin, pass);
    if (pass.empty()) { std::cerr << "Empty passphrase; abort.\n"; return 6; }

    // derive masterKey
    std::string masterKey;
    try { masterKey = derive_master_key(pass, salt); } catch (const std::exception &e) {
        std::cerr << "Key derivation failed: " << e.what() << "\n"; return 7;
    }

    // attempt to load wrapped_logkey (optional)
    std::string wrapped_log_path = "modules/emergency_messenger/keys/wrapped_logkey.bin";
    bool have_logkey = false;
    std::string logKey;
    if (fs::exists(wrapped_log_path)) {
        try {
            auto wrapped = read_binary_file(wrapped_log_path);
            std::string wrapped_str((char*)wrapped.data(), wrapped.size());
            // unwrap using masterKey
            logKey = decrypt_aead(wrapped_str, masterKey);
            have_logkey = true;
            std::cout << "Unwrapped logKey successfully; will encrypt records with logKey.\n";
        } catch (const std::exception &e) {
            std::cerr << "Warning: failed to unwrap wrapped_logkey.bin: " << e.what()
                      << "\nFalling back to using masterKey to encrypt records.\n";
            have_logkey = false;
        }
    } else {
        std::cout << "No wrapped_logkey.bin found — will use masterKey to encrypt log records.\n";
    }

    // backup original log
    fs::create_directories("backups");
    std::string backup = "backups/sent_messages_plain_" + std::to_string(std::time(nullptr)) + ".log";
    try {
        fs::copy_file(path, backup, fs::copy_options::overwrite_existing);
        std::cout << "Backed up plaintext log to: " << backup << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Warning: could not backup original log: " << e.what() << "\n";
    }

    // open original log and parse
    std::ifstream infile(path, std::ios::binary);
    if (!infile.is_open()) {
        std::cerr << "Unable to open log file for reading: " << path << "\n";
        sodium_memzero((void*)masterKey.data(), masterKey.size());
        return 8;
    }

    std::vector<std::pair<std::string,std::string>> records; // (ts, content-with-priority)
    std::string line;
    std::string pending_ts;
    while (std::getline(infile, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (is_timestamp_line(line)) {
            pending_ts = line;
            continue;
        }

        // line may already be "ctime : message [Priority: N]" or just " : message [Priority:N]"
        // Try to detect presence of "[Priority:"
        if (line.find("[Priority:") != std::string::npos) {
            std::string ts = pending_ts;
            if (ts.empty()) {
                // maybe the line itself has a timestamp prefix before " : "
                size_t sep = line.find(" : ");
                if (sep != std::string::npos) {
                    std::string possible_ts = line.substr(0, sep);
                    if (is_timestamp_line(possible_ts)) {
                        ts = possible_ts;
                        line = line.substr(sep + 3); // keep remainder as content
                    }
                }
            }
            records.emplace_back(ts, line);
            pending_ts.clear();
        } else {
            // fallback: treat the line as a content line
            std::string ts = pending_ts;
            records.emplace_back(ts, line);
            pending_ts.clear();
        }
    }
    infile.close();

    // open tmp output
    std::string tmp = path + ".tmp";
    std::ofstream outfile(tmp, std::ios::binary | std::ios::trunc);
    if (!outfile.is_open()) {
        std::cerr << "Unable to open temporary output file: " << tmp << "\n";
        sodium_memzero((void*)masterKey.data(), masterKey.size());
        return 9;
    }

    // regex for priority
    std::regex prio_re(R"(\[Priority:\s*(\d+)\])");

    for (auto &p : records) {
        std::string ts = p.first;
        std::string content = p.second;

        if (ts.empty()) {
            std::time_t now = std::time(nullptr);
            ts = std::string(std::ctime(&now));
            if (!ts.empty() && ts.back() == '\n') ts.pop_back();
        }

        // extract priority
        std::smatch m;
        int priority = 2;
        if (std::regex_search(content, m, prio_re) && m.size() >= 2) {
            priority = std::stoi(m[1].str());
            content = std::regex_replace(content, prio_re, "");
        }
        // remove leading " : " or similar
        size_t pos = content.find_first_not_of(" :\t");
        if (pos != std::string::npos) content = content.substr(pos);
        else content.clear();

        // now content is the plaintext message
        std::string record_plain = ts + " : " + content + " [Priority: " + std::to_string(priority) + "]";

        try {
            std::string boxed;
            if (have_logkey) boxed = encrypt_aead(record_plain, logKey);
            else boxed = encrypt_aead(record_plain, masterKey);

            std::string b64 = binToBase64(reinterpret_cast<const unsigned char*>(boxed.data()), boxed.size());
            outfile << b64 << "\n";
        } catch (const std::exception &e) {
            std::cerr << "Encryption failed for record: " << e.what() << "\n";
            // write nothing for this record; continue
        }
    }

    outfile.close();

    // atomically replace
    try {
        fs::rename(tmp, path);
    } catch (const std::exception &e) {
        std::cerr << "Failed to overwrite original log with sanitized log: " << e.what() << "\n";
        sodium_memzero((void*)masterKey.data(), masterKey.size());
        return 10;
    }

    sodium_memzero((void*)masterKey.data(), masterKey.size());
    if (have_logkey) sodium_memzero((void*)logKey.data(), logKey.size());

    std::cout << "Re-encryption complete. Log sanitized and original backed up at: " << backup << "\n";
    return 0;
}
