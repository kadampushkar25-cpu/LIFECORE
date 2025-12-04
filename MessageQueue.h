// MessageQueue.h
#ifndef MESSAGEQUEUE_H
#define MESSAGEQUEUE_H

#include <string>
#include <vector>

struct Message {
    std::string text; // ciphertext (nonce||ciphertext)
    int priority;
};

class MessageQueue {
public:
    MessageQueue(const std::string &masterKey, const std::string &logKey);
    ~MessageQueue();

    void addMessage(const std::string &content, int priority);
    void sendMessages();
    void showQueue();
    void saveMessagesToFile(const std::string &filepath);
    void loadMessagesFromFile(const std::string &filepath);
    void viewSentHistory();

private:
    std::vector<Message> messages;
    std::vector<Message> sentMessages;
    std::string masterKey;
    std::string logKey;
};

#endif // MESSAGEQUEUE_H
