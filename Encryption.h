// Encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>
#include <fstream>
#include <cstring>

static const size_t SALT_LEN = crypto_pwhash_SALTBYTES; // 16
static const size_t MASTER_KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32

inline void init_crypto() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

// --- Salt helpers ---
inline std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> s(SALT_LEN);
    randombytes_buf(s.data(), SALT_LEN);
    return s;
}
inline void write_binary_file(const std::string &path, const std::vector<unsigned char> &buf) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) throw std::runtime_error("failed to open file for writing: " + path);
    f.write((const char*)buf.data(), buf.size());
    f.close();
}
inline std::vector<unsigned char> read_binary_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) throw std::runtime_error("failed to open file for reading: " + path);
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<unsigned char> buf(size);
    if (!f.read((char*)buf.data(), size)) throw std::runtime_error("failed to read file: " + path);
    f.close();
    return buf;
}

// --- Argon2id (crypto_pwhash) KDF: derive master key from passphrase + salt ---
inline std::string derive_master_key(const std::string &pass, const std::vector<unsigned char> &salt) {
    if (salt.size() != SALT_LEN) throw std::runtime_error("salt size mismatch");
    std::string key(MASTER_KEY_LEN, '\0');
    if (crypto_pwhash((unsigned char*)key.data(), key.size(),
                      pass.c_str(), pass.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("crypto_pwhash failed - out of memory");
    }
    return key;
}

// --- Base64 helpers (libsodium) ---
inline std::string binToBase64(const unsigned char *bin, size_t binlen) {
    size_t out_len = sodium_base64_encoded_len(binlen, sodium_base64_VARIANT_ORIGINAL);
    std::string out(out_len, '\0');
    sodium_bin2base64(&out[0], out_len, bin, binlen, sodium_base64_VARIANT_ORIGINAL);
    out.resize(strlen(out.c_str()));
    return out;
}
inline std::vector<unsigned char> base64ToBin(const std::string &b64) {
    size_t bin_maxlen = b64.size();
    std::vector<unsigned char> bin(bin_maxlen);
    size_t bin_len = 0;
    if (sodium_base642bin(bin.data(), bin_maxlen,
                          b64.c_str(), b64.size(),
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Base64 decode failed");
    }
    bin.resize(bin_len);
    return bin;
}

// --- AEAD encrypt/decrypt: returns nonce||ciphertext or decrypts same ---
inline std::string encrypt_aead(const std::string &plaintext, const std::string &key) {
    if (key.size() != MASTER_KEY_LEN) throw std::runtime_error("Invalid key size");
    std::string nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, '\0');
    randombytes_buf(&nonce[0], nonce.size());
    size_t max_ct_len = plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::vector<unsigned char> ciphertext(max_ct_len);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        (const unsigned char*)plaintext.data(), plaintext.size(),
        NULL, 0, NULL,
        (const unsigned char*)nonce.data(),
        (const unsigned char*)key.data()
    );
    std::string out = nonce;
    out.append((char*)ciphertext.data(), (size_t)clen);
    return out;
}
inline std::string decrypt_aead(const std::string &boxed, const std::string &key) {
    if (key.size() != MASTER_KEY_LEN) throw std::runtime_error("Invalid key size");
    if (boxed.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("Ciphertext too short");
    const unsigned char* nonce = (const unsigned char*)boxed.data();
    const unsigned char* cdata = (const unsigned char*)(boxed.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    size_t csize = boxed.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    std::vector<unsigned char> decrypted(csize);
    unsigned long long dlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &dlen, NULL,
            cdata, csize, NULL, 0,
            nonce, (const unsigned char*)key.data()) != 0) {
        throw std::runtime_error("Decryption failed (auth)");
    }
    return std::string((char*)decrypted.data(), (size_t)dlen);
}

#endif // ENCRYPTION_H
