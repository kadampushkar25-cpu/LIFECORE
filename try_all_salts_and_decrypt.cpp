// try_all_salts_and_decrypt.cpp
// Searches for candidate salt files under repo, derives masterKey for each using the passphrase,
// tries to unwrap wrapped_logkey.bin in same directory (if present) and attempts to decrypt
// the last log record inner message. Prints any successful decrypts.

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

static std::vector<fs::path> find_files(const fs::path &root, const std::vector<std::string> &patterns) {
    std::vector<fs::path> found;
    for (auto &p : fs::recursive_directory_iterator(root)) {
        if (!p.is_regular_file()) continue;
        std::string name = p.path().filename().string();
        for (auto &pat : patterns) {
            if (name.find(pat) != std::string::npos) {
                found.push_back(p.path());
            }
        }
    }
    return found;
}

int main() {
    try { init_crypto(); } catch (const std::exception &e) { std::cerr<<"libsodium init failed: "<<e.what()<<"\n"; return 1; }

    const std::string logpath = "modules/emergency_messenger/logs/sent_messages.log";
    if (!fs::exists(logpath)) { std::cerr << "Log not found: " << logpath << "\n"; return 2; }
    std::string lastline = read_last_line(logpath);
    if (lastline.empty()) { std::cerr << "No lines found in log\n"; return 3; }

    std::vector<unsigned char> wrapped_bin;
    try { wrapped_bin = base64ToBin(lastline); } catch (const std::exception &e) { std::cerr << "Last line not base64: " << e.what() << "\n"; return 4; }
    std::string wrapped_str((char*)wrapped_bin.data(), wrapped_bin.size());

    std::cout << "Found last log line (len=" << wrapped_str.size() << " bytes). Searching for candidate salts...\n";

    // search patterns for salt files (common names)
    std::vector<std::string> patterns = {"salt", "user_salt", "user_salt.bin"};
    auto salt_files = find_files(".", patterns);

    if (salt_files.empty()) {
        std::cerr << "No candidate salt files found under repo.\n";
    } else {
        std::cout << "Candidate salts found:\n";
        for (auto &s : salt_files) std::cout << " - " << s.string() << "\n";
    }

    // also look for wrapped_logkey backups
    std::vector<std::string> wrap_patterns = {"wrapped_logkey", "wrapped_logkey.bin"};
    auto wrapped_candidates = find_files(".", wrap_patterns);
    if (!wrapped_candidates.empty()) {
        std::cout << "Found wrapped_logkey candidates:\n";
        for (auto &w : wrapped_candidates) std::cout << " - " << w.string() << "\n";
    }

    std::string pass;
    std::cout << "Enter the passphrase you always use: ";
    std::getline(std::cin, pass);
    if (pass.empty()) { std::cerr << "Empty passphrase\n"; return 5; }

    bool any_success = false;

    // function to attempt decrypt given masterKey and optional wrapped_logpath
    auto attempt_with = [&](const std::string &label, const std::string &masterKey, const fs::path *wrapped_path) -> bool {
        std::string logKey;
        bool have_logkey = false;
        if (wrapped_path && fs::exists(*wrapped_path)) {
            try {
                auto w = read_binary_file(wrapped_path->string());
                std::string wstr((char*)w.data(), w.size());
                logKey = decrypt_aead(wstr, masterKey);
                have_logkey = true;
                std::cout << "[" << label << "] Unwrapped logKey successfully.\n";
            } catch (const std::exception &e) {
                std::cerr << "[" << label << "] Failed to unwrap logKey: " << e.what() << "\n";
                have_logkey = false;
            }
        }

        // decrypt outer wrapper
        std::string record_plain;
        try {
            if (have_logkey) record_plain = decrypt_aead(wrapped_str, logKey);
            else record_plain = decrypt_aead(wrapped_str, masterKey);
        } catch (const std::exception &e) {
            std::cerr << "[" << label << "] Failed to decrypt outer record: " << e.what() << "\n";
            return false;
        }

        std::cout << "[" << label << "] Decrypted outer record:\n" << record_plain << "\n";

        // extract inner b64 message
        std::smatch m;
        std::regex re(R"(\s:\s([A-Za-z0-9+/=]+)\s*\[Priority:\s*(\d+)\])");
        if (!std::regex_search(record_plain, m, re) || m.size() < 2) {
            std::cerr << "[" << label << "] Could not find inner base64 message in record (unexpected format)\n";
            return false;
        }
        std::string b64msg = m[1].str();
        try {
            auto bin = base64ToBin(b64msg);
            std::string inner_box((char*)bin.data(), bin.size());
            // try decrypt inner with masterKey
            try {
                std::string plaintext = decrypt_aead(inner_box, masterKey);
                std::cout << "[" << label << "] SUCCESS: inner message decrypted with masterKey. Plaintext:\n" << plaintext << "\n";
                return true;
            } catch (...) {
                // try with logKey as backup (unlikely)
                if (have_logkey) {
                    try {
                        std::string plaintext2 = decrypt_aead(inner_box, logKey);
                        std::cout << "[" << label << "] SUCCESS: inner message decrypted with logKey. Plaintext:\n" << plaintext2 << "\n";
                        return true;
                    } catch (...) {}
                }
                std::cerr << "[" << label << "] Inner message decryption failed with both masterKey/logKey.\n";
                return false;
            }
        } catch (const std::exception &e) {
            std::cerr << "[" << label << "] Failed to base64-decode inner message: " << e.what() << "\n";
            return false;
        }
    };

    // try each salt file and, for each, try any wrapped_logkey in the same directory or repo-wide
    for (auto &saltp : salt_files) {
        std::vector<unsigned char> salt;
        try { salt = read_binary_file(saltp.string()); } catch (...) { continue; }
        std::string mk;
        try { mk = derive_master_key(pass, salt); } catch (const std::exception &e) { std::cerr << "Argon2 failed for salt " << saltp << ": " << e.what() << "\n"; continue; }

        // try using wrapped_logkey in same parent dir
        fs::path parent = saltp.parent_path();
        fs::path local_wrapped = parent / "wrapped_logkey.bin";
        if (fs::exists(local_wrapped)) {
            std::string label = "salt=" + saltp.string() + " wrapped(local)";
            if (attempt_with(label, mk, &local_wrapped)) { any_success = true; break; }
        }

        // try repo-wide wrapped candidates
        for (auto &w : wrapped_candidates) {
            std::string label = "salt=" + saltp.string() + " wrapped=" + w.string();
            if (attempt_with(label, mk, &w)) { any_success = true; break; }
        }
        if (any_success) break;

        // try with no wrapped key (use masterKey directly)
        {
            std::string label = "salt=" + saltp.string() + " (no wrapped key)";
            if (attempt_with(label, mk, nullptr)) { any_success = true; break; }
        }
    }

    if (!any_success) {
        std::cerr << "No successful decryption with discovered salts/wrapped keys.\n";
        std::cerr << "If you have other salt files or older backups, place them under the repo and re-run this tool.\n";
    }

    return any_success ? 0 : 9;
}
