#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <chrono>

namespace Utils {
    namespace Colors {
        const std::string RESET = "\033[0m";
        const std::string RED = "\033[31m";
        const std::string GREEN = "\033[32m";
        const std::string YELLOW = "\033[33m";
        const std::string BLUE = "\033[34m";
        const std::string MAGENTA = "\033[35m";
        const std::string CYAN = "\033[36m";
        const std::string WHITE = "\033[37m";
        const std::string BOLD = "\033[1m";
    }
    
    std::string formatTimestamp(const std::chrono::system_clock::time_point& tp);
    std::string formatBytes(uint32_t bytes);
    std::string protocolToString(int protocol);
    std::string macToString(const uint8_t* mac);
    void playBeep();
    void clearScreen();
    std::vector<std::string> splitString(const std::string& str, char delimiter);
    bool isValidIP(const std::string& ip);
    bool isValidPort(const std::string& port);
    bool isValidProtocol(const std::string& protocol);
    std::string toUpperCase(const std::string& str);
    std::string getCurrentDateTime();
}

#endif
