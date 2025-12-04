// rotate_keys.cpp
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "Encryption.h"

namespace fs = std::filesystem;

int main() {
    try { init_crypto(); } catch (const std::exception &e) { std::cerr<<e.what()<<"\n"; return 1; }
    std::string keydir = "modules/emergency_messenger/keys";
    fs::create_directories(keydir);
    std::string salt_path = keydir + "/user_salt.bin";
    if (!fs::exists(salt_path)) { std::cerr << "Salt not found: " << salt_path << "\n"; return 2; }
    auto salt = read_binary_file(salt_path);

    std::string oldp, newp;
    std::cout << "Old passphrase: "; std::getline(std::cin, oldp);
    std::cout << "New passphrase: "; std::getline(std::cin, newp);

    std::string old_master = derive_master_key(oldp, salt);
    std::string new_master = derive_master_key(newp, salt);

    std::string wrapped_path = keydir + "/wrapped_logkey.bin";
    if (!fs::exists(wrapped_path)) { std::cerr << "Wrapped log key not found: " << wrapped_path << "\n"; return 3; }
    auto wrapped = read_binary_file(wrapped_path);
    std::string wrapped_str((char*)wrapped.data(), wrapped.size());

    try {
        std::string logKey = decrypt_aead(wrapped_str, old_master);
        std::string new_wrapped = encrypt_aead(logKey, new_master);
        std::string backup = wrapped_path + ".bak";
        fs::rename(wrapped_path, backup);
        std::vector<unsigned char> nb(new_wrapped.begin(), new_wrapped.end());
        write_binary_file(wrapped_path, nb);
        sodium_memzero((void*)old_master.data(), old_master.size());
        sodium_memzero((void*)new_master.data(), new_master.size());
        sodium_memzero((void*)logKey.data(), logKey.size());
        std::cout << "Rewrapped logKey. Backup created: " << backup << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Failed rewrap: " << e.what() << "\n";
        return 4;
    }
    return 0;
}
