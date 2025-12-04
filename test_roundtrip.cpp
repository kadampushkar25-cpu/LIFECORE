// test_roundtrip.cpp
#include <iostream>
#include "Encryption.h"

int main() {
    try { init_crypto(); } catch (...) { std::cerr<<"libsodium init failed\n"; return 2; }

    // test salt + argon2
    auto salt = generate_salt();
    std::string key = derive_master_key("testpass", salt);
    std::string pt = "This is a test message";
    std::string boxed = encrypt_aead(pt, key);
    std::string recovered = decrypt_aead(boxed, key);
    std::cout << "Original: " << pt << "\nRecovered: " << recovered << "\n";
    return (pt == recovered) ? 0 : 3;
}
