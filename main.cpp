#include "MessageQueue.h"
#include <iostream>
#include <string>
#include <sodium.h>

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium!" << std::endl;
        return 1;
    }

    // Ask user for a key (any length)
    std::string userKey;
    std::cout << "Enter encryption key (any length, will be adjusted to 32 bytes): ";
    std::getline(std::cin, userKey);

    // Ensure key is exactly 32 bytes
    std::string encryptionKey = userKey.substr(0, 32);               // truncate if longer
    encryptionKey.append(32 - encryptionKey.size(), '0');           // pad with '0' if shorter

    // Create MessageQueue with valid key
    MessageQueue mq(encryptionKey);

    int choice;
    do {
        std::cout << "\n--- Emergency Messenger ---\n";
        std::cout << "1. Add Emergency Message\n";
        std::cout << "2. Send Messages\n";
        std::cout << "3. Show Message Queue\n";
        std::cout << "4. Exit\n";
        std::cout << "5. View Sent Message History\n";
        std::cout << "Enter choice: ";
        std::cin >> choice;
        std::cin.ignore();  // clear newline from input buffer

        if (choice == 1) {
            std::string msg;
            int priority;
            std::cout << "Enter message content: ";
            std::getline(std::cin, msg);
            std::cout << "Priority (1 = High, 2 = Medium, 3 = Low): ";
            std::cin >> priority;
            std::cin.ignore();

            mq.addMessage(msg, priority);
        } else if (choice == 2) {
            mq.sendMessages();
        } else if (choice == 3) {
            mq.showQueue();
        } else if (choice == 5) {
            mq.viewSentHistory();
        }
    } while (choice != 4);

    return 0;
}
