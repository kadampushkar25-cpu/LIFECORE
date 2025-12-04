// Vault.h
#ifndef VAULT_H
#define VAULT_H

#include "Encryption.h"
#include <string>
#include <fstream>

inline void save_vault(const std::string &path, const std::string &jsondata, const std::string &masterKey) {
    std::string boxed = encrypt_aead(jsondata, masterKey);
    std::string b64 = binToBase64((const unsigned char*)boxed.data(), boxed.size());
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << b64;
    f.close();
}

inline std::string load_vault(const std::string &path, const std::string &masterKey) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "{}";
    std::string b64;
    std::getline(f, b64);
    f.close();
    if (b64.empty()) return "{}";
    auto bin = base64ToBin(b64);
    std::string boxed((char*)bin.data(), bin.size());
    return decrypt_aead(boxed, masterKey);
}

#endif // VAULT_H
