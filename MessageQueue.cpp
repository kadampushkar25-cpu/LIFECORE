#include "MessageQueue.h"
#include "Encryption.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <ctime>

void MessageQueue::addMessage(const std::string &content, int priority)
{
    std::string encrypted = encrypt(content, encryptionKey);
    Message msg{encrypted, priority};
    messages.push_back(msg);
    std::cout << "Message added to queue.\n";
}

void MessageQueue::sendMessages()
{
    if (messages.empty())
    {
        std::cout << "No messages to send.\n";
        return;
    }

    std::ofstream log("modules/emergency_messenger/logs/sent_messages.log", std::ios::app);

    // Sort by priority (1 high → 3 low)
    std::sort(messages.begin(), messages.end(),
              [](const Message &a, const Message &b)
              { return a.priority < b.priority; });

    for (const auto &msg : messages)
    {
        try
        {
            std::string decrypted = decrypt(msg.text, encryptionKey);
            std::time_t now = std::time(nullptr);

            std::cout << "Sending: " << decrypted << " [Priority: " << msg.priority << "]\n";

            if (log.is_open())
            {
                log << std::ctime(&now) << " : " << decrypted << " [Priority: " << msg.priority << "]\n";
            }

            // Add message to sent history
            sentMessages.push_back(msg);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Failed to decrypt message: " << e.what() << "\n";
        }
    }

    messages.clear();
    log.close();
}


void MessageQueue::showQueue()
{
    if (messages.empty())
    {
        std::cout << "Queue is empty.\n";
        return;
    }

    std::cout << "--- Current Queue ---\n";
    for (const auto &msg : messages)
    {
        try
        {
            std::cout << decrypt(msg.text, encryptionKey) << " (Priority: " << msg.priority << ")\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error decrypting message: " << e.what() << "\n";
        }
    }
}

void MessageQueue::loadMessagesFromFile(const std::string &filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open())
        return;

    std::string line;
    while (std::getline(file, line))
    {
        if (!line.empty())
        {
            Message msg{line, 2}; // default medium priority
            messages.push_back(msg);
        }
    }
    file.close();
}

void MessageQueue::saveMessagesToFile(const std::string &filepath)
{
    std::ofstream file(filepath, std::ios::binary);
    for (const auto &msg : messages)
    {
        file << msg.text << "\n";
    }
    file.close();
}
void MessageQueue::viewSentHistory()
{
    if (sentMessages.empty())
    {
        std::cout << "No messages have been sent yet.\n";
        return;
    }

    std::cout << "--- Sent Messages ---\n";
    for (const auto &msg : sentMessages)
    {
        try
        {
            std::cout << decrypt(msg.text, encryptionKey)
                      << " (Priority: " << msg.priority << ")\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error decrypting sent message: " << e.what() << "\n";
        }
    }
}
