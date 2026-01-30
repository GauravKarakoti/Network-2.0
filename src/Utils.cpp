#include "Utils.h"
#include <iomanip>
#include <sstream>
#include <iostream>
#include <regex>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdlib>
#endif

std::string Utils::formatTimestamp(const std::chrono::system_clock::time_point& tp) {
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Utils::formatBytes(uint32_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    
    std::stringstream ss;
    if (unit == 0) {
        ss << static_cast<int>(size) << " " << units[unit];
    } else {
        ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    }
    return ss.str();
}

std::string Utils::protocolToString(int protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER(" + std::to_string(protocol) + ")";
    }
}

std::string Utils::macToString(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

void Utils::playBeep() {
#ifdef _WIN32
    Beep(800, 300);
#else
    std::cout << "\a" << std::flush;
#endif
}

void Utils::clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

std::vector<std::string> Utils::splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

bool Utils::isValidIP(const std::string& ip) {
    std::regex ipRegex(R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    return std::regex_match(ip, ipRegex);
}

bool Utils::isValidPort(const std::string& port) {
    try {
        int p = std::stoi(port);
        return p >= 0 && p <= 65535;
    } catch (...) {
        return false;
    }
}

std::string Utils::getCurrentDateTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string Utils::toUpperCase(const std::string& str) {
    std::string result = str;
    for (char& c : result) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return result;
}

bool Utils::isValidProtocol(const std::string& protocol) {
    std::string upper = toUpperCase(protocol);
    return (upper == "TCP" || upper == "UDP" || upper == "ICMP");
}
