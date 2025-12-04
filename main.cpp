// main.cpp
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include "Encryption.h"
#include "MessageQueue.h"
#include <limits>

namespace fs = std::filesystem;

static std::string read_text_file(const std::string &p) {
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) return "";
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}
static void write_text_file(const std::string &p, const std::string &s) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << s; f.close();
}

int main() {
    try { init_crypto(); } catch (const std::exception &e) { std::cerr<<"Crypto init failed: "<<e.what()<<"\n"; return 1; }

    fs::create_directories("modules/emergency_messenger/keys");
    fs::create_directories("modules/emergency_messenger/logs");

    std::string salt_path = "modules/emergency_messenger/keys/user_salt.bin";
    std::vector<unsigned char> salt;
    if (!fs::exists(salt_path)) {
        salt = generate_salt();
        write_binary_file(salt_path, salt);
        std::cout << "Generated new user salt.\n";
    } else {
        salt = read_binary_file(salt_path);
    }

    std::string pass;
    std::cout << "Enter passphrase (used to derive master key): ";
    std::getline(std::cin, pass);
    std::string masterKey;
    try {
        masterKey = derive_master_key(pass, salt);
    } catch (const std::exception &e) {
        std::cerr << "Key derivation failed: " << e.what() << "\n";
        return 2;
    }

    std::string wrapped_log_path = "modules/emergency_messenger/keys/wrapped_logkey.bin";
    std::string logKey;
    if (fs::exists(wrapped_log_path)) {
        try {
            auto wrapped = read_binary_file(wrapped_log_path);
            std::string wrapped_str((char*)wrapped.data(), wrapped.size());
            logKey = decrypt_aead(wrapped_str, masterKey); // unwrap
            std::cout << "Loaded and unwrapped log key.\n";
        } catch (const std::exception &e) {
            std::cerr << "Failed to unwrap existing log key: " << e.what() << "\n";
            return 3;
        }
    } else {
        // generate random logKey and wrap it
        std::string new_logKey(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, '\0');
        randombytes_buf(&new_logKey[0], new_logKey.size());
        std::string wrapped = encrypt_aead(new_logKey, masterKey);
        std::vector<unsigned char> wrapped_bin(wrapped.begin(), wrapped.end());
        write_binary_file(wrapped_log_path, wrapped_bin);
        logKey = new_logKey;
        std::cout << "Generated and wrapped new log key.\n";
    }

    // create message queue with both keys
    MessageQueue mq(masterKey, logKey);

    // menu loop
    while (true) {
        std::cout << "\nMenu:\n1) Add message\n2) Show queue\n3) Send messages\n4) Save queue\n5) Load queue\n6) View sent history\n7) Exit\nChoose: ";
        int c;
        if (!(std::cin >> c)) break;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (c == 1) {
            std::string msg;
            int pr;
            std::cout << "Enter message: ";
            std::getline(std::cin, msg);
            std::cout << "Priority (1 high, 2 med, 3 low): ";
            std::cin >> pr; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            mq.addMessage(msg, pr);
        } else if (c == 2) {
            mq.showQueue();
        } else if (c == 3) {
            mq.sendMessages();
        } else if (c == 4) {
            mq.saveMessagesToFile("messages.store");
        } else if (c == 5) {
            mq.loadMessagesFromFile("messages.store");
        } else if (c == 6) {
            mq.viewSentHistory();
        } else break;
    }

    sodium_memzero((void*)masterKey.data(), masterKey.size());
    sodium_memzero((void*)logKey.data(), logKey.size());
    return 0;
}
