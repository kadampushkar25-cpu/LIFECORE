#ifndef MESSAGEQUEUE_H
#define MESSAGEQUEUE_H

#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include "Encryption.h"

struct Message {
    std::string text;
    int priority;
};

class MessageQueue {
private:
    std::string encryptionKey;
    std::vector<Message> messages;
    std::vector<Message> sentMessages;

public:
    // Constructor
    MessageQueue(const std::string &key) : encryptionKey(key) {}

    // Member functions
    void addMessage(const std::string &content, int priority);
    void sendMessages();
    void showQueue();
    void viewSentHistory();
    void loadMessagesFromFile(const std::string &filepath);
    void saveMessagesToFile(const std::string &filepath);
};

#endif
