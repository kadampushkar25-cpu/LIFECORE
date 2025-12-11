// Encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>

// Uses libsodium's crypto_aead_xchacha20poly1305_ietf_* API

inline void init_crypto() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

// key: 32 bytes binary string (not hex). Store/load from env or secure file
inline std::string encrypt(const std::string &plaintext, const std::string &key) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid key size");
    }
    std::string nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\0');
    randombytes_buf(&nonce[0], nonce.size());

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        (const unsigned char*)plaintext.data(), plaintext.size(),
        NULL, 0, // additional data (optional)
        NULL, // nsec
        (const unsigned char*)nonce.data(),
        (const unsigned char*)key.data()
    );

    // result = nonce || ciphertext
    std::string out = nonce;
    out.append((char*)ciphertext.data(), clen);
    return out;
}

inline std::string decrypt(const std::string &boxed, const std::string &key) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid key size");
    }
    if (boxed.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("Ciphertext too short");
    }

    const unsigned char* nonce = (const unsigned char*)boxed.data();
    const unsigned char* cdata = (const unsigned char*)(boxed.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    size_t csize = boxed.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    std::vector<unsigned char> decrypted(csize); 
    unsigned long long dlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &dlen,
            NULL,
            cdata, csize,
            NULL, 0,
            nonce,
            (const unsigned char*)key.data()) != 0) {
        throw std::runtime_error("Decryption failed (auth)");
    }
    return std::string((char*)decrypted.data(), dlen);
}

#endif // ENCRYPTION_H
