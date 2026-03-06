#include "PacketCapture.h"
#include "AnomalyDetector.h"
#include "NetworkStats.h"
#include "WatchRules.h"
#include "Logger.h"
#include "Utils.h"
#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <vector>

class NetworkMonitor {
private:
    PacketCapture capture;
    AnomalyDetector anomalyDetector;
    NetworkStats stats;
    WatchRules watchRules;
    Logger logger;
    std::string protocolFilter;  // Empty = no filter, "TCP", "UDP", or "ICMP"
    
    std::atomic<bool> running{false};
    bool isSilentMode{false};
    std::queue<PacketInfo> packetQueue;
    std::mutex queueMutex;
    
    static constexpr size_t MAX_DISPLAY_PACKETS = 20;
    PacketInfo recentPackets[MAX_DISPLAY_PACKETS];
    size_t currentIndex = 0;
    
    void processPacket(const PacketInfo& packet);
    void displayLoop();
    void handleUserInput();
    
public:
    NetworkMonitor() = default;
    
    bool initialize(const std::string& interface);
    void start();
    void stop();
    void printHelp() const;
    bool parseArguments(int argc, char* argv[]);
};

NetworkMonitor* g_monitor = nullptr;

void signalHandler(int signum) {
    std::cout << "\nShutting down gracefully..." << std::endl;
    if (g_monitor) {
        g_monitor->stop();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    NetworkMonitor monitor;
    g_monitor = &monitor;
    
    signal(SIGINT, signalHandler);
#ifndef _WIN32
    signal(SIGTERM, signalHandler);
#endif
    
    std::cout << Utils::Colors::BOLD << Utils::Colors::CYAN
              << "=== Network 2.0 v1.0 ===" << Utils::Colors::RESET << std::endl;
    std::cout << "Advanced packet capture and anomaly detection tool\n" << std::endl;
    
    if (!monitor.parseArguments(argc, argv)) {
        monitor.printHelp();
        return 1;
    }
    
    if (!monitor.initialize("")) {
        std::cout << Utils::Colors::RED << "Failed to initialize Network 2.0" 
                  << Utils::Colors::RESET << std::endl;
        return 1;
    }
    
    monitor.start();
    return 0;
}

bool NetworkMonitor::parseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printHelp();
            return false;
        } else if (arg == "--silent") {
            isSilentMode = true;
            std::cout << Utils::Colors::GREEN << "Silent mode enabled. Live traffic table suppressed." 
                      << Utils::Colors::RESET << std::endl;
        } else if (arg == "--watch-ip" && i + 1 < argc) {
            std::string ip = argv[++i];
            if (!Utils::isValidIP(ip)) {
                std::cerr << Utils::Colors::RED << "Error: Invalid IP address '" << ip << "'" 
                          << Utils::Colors::RESET << std::endl;
                std::cerr << "Expected format: xxx.xxx.xxx.xxx (e.g., 192.168.1.10)" << std::endl;
                return false;
            }
            watchRules.addWatchIP(ip);
        } else if (arg == "--alert-port" && i + 1 < argc) {
            std::string portStr = argv[++i];
            if (!Utils::isValidPort(portStr)) {
                std::cerr << Utils::Colors::RED << "Error: Invalid port number '" << portStr << "'"
                          << Utils::Colors::RESET << std::endl;
                std::cerr << "Port must be a number between 0 and 65535" << std::endl;
                return false;
            }
            uint16_t port = static_cast<uint16_t>(std::stoi(portStr));
            watchRules.addWatchPort(port);
        } else if (arg == "--log" && i + 1 < argc) {
            logger.enableLogging(argv[++i]);
        } else if (arg == "--interface" && i + 1 < argc) {
            i++;
        } else if (arg == "--protocol" && i + 1 < argc) {
            std::string proto = argv[++i];
            if (!Utils::isValidProtocol(proto)) {
                std::cerr << Utils::Colors::RED << "Error: Invalid protocol '" << proto << "'"
                          << Utils::Colors::RESET << std::endl;
                std::cerr << "Valid protocols: TCP, UDP, ICMP" << std::endl;
                return false;
            }
            protocolFilter = Utils::toUpperCase(proto);
            std::cout << Utils::Colors::GREEN << "Filtering for protocol: " 
                      << protocolFilter << Utils::Colors::RESET << std::endl;
        } else {
            std::cout << Utils::Colors::RED << "Unknown argument: " << arg 
                      << Utils::Colors::RESET << std::endl;
            return false;
        }
    }
    
    return true;
}

void NetworkMonitor::printHelp() const {
    std::cout << "Usage: network2.0 [OPTIONS]\n\n"
              << "Options:\n"
              << "  --help, -h              Show this help message\n"
              << "  --silent                Run in silent mode (suppress live traffic table)\n"
              << "  --watch-ip <IP>         Watch traffic for specific IP address\n"
              << "  --alert-port <PORT>     Alert on traffic to/from specific port\n"
              << "  --log <filename>        Enable logging to CSV file\n"
              << "  --interface <name>      Specify network interface\n"
              << "  --protocol <TYPE>       Filter by protocol (TCP, UDP, ICMP)\n\n"
              << "Interactive Commands:\n"
              << "  h, help                 Show help\n"
              << "  s, stats                Show detailed statistics\n"
              << "  w, watch                Show current watch rules\n"
              << "  a, anomalies           Show anomaly detection status\n"
              << "  r, reset               Reset all statistics\n"
              << "  l, log <filename>      Enable/disable logging\n"
              << "  e, export <filename>   Export captured data to CSV\n"
              << "  q, quit                Quit the program\n\n"
              << "Examples:\n"
              << "  network2.0 --watch-ip 192.168.1.10 --log traffic.csv\n"
              << "  network2.0 --alert-port 8080 --interface eth0\n";
}

bool NetworkMonitor::initialize(const std::string& interface) {
    if (!capture.initialize(interface)) {
        return false;
    }
    
    capture.onPacketReceived = [this](const PacketInfo& packet) {
        std::lock_guard<std::mutex> lock(queueMutex);
        packetQueue.push(packet);
    };
    
    watchRules.printWatchedItems();
    return true;
}

void NetworkMonitor::start() {
    running = true;
    
    std::thread captureThread([this]() {
        capture.startCapture();
    });
    
    std::thread displayThread([this]() {
        displayLoop();
    });
    
    handleUserInput();
    
    running = false;
    capture.stopCapture();
    
    if (captureThread.joinable()) {
        captureThread.join();
    }
    if (displayThread.joinable()) {
        displayThread.join();
    }
}

void NetworkMonitor::stop() {
    running = false;
    capture.stopCapture();
}

void NetworkMonitor::processPacket(const PacketInfo& packet) {
    // Apply protocol filter if set
    if (!protocolFilter.empty() && packet.protocol != protocolFilter) {
        return;  // Skip packets that don't match the filter
    }
    
    PacketInfo processedPacket = packet;
    
    anomalyDetector.analyzePacket(processedPacket);
    
    if (watchRules.checkPacket(processedPacket)) {
        
    }
    
    
    stats.recordPacket(processedPacket);
    
  
    if (logger.isEnabled()) {
        logger.logPacket(processedPacket);
    }
    

    recentPackets[currentIndex] = processedPacket;
    currentIndex = (currentIndex + 1) % MAX_DISPLAY_PACKETS;
}

void NetworkMonitor::displayLoop() {
    while (running) {
        std::queue<PacketInfo> localQueue;
        
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            std::swap(localQueue, packetQueue);
        }

        while (!localQueue.empty()) {
            processPacket(localQueue.front());
            localQueue.pop();
        }
        
        if (!isSilentMode) {
            size_t displayCount = (std::min)(stats.getTotalPackets(), 
                                         static_cast<uint64_t>(MAX_DISPLAY_PACKETS));
            stats.printLiveTable(recentPackets, displayCount);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void NetworkMonitor::handleUserInput() {
    std::string input;
    std::cout << "\nPress 'h' for help, 'q' to quit: ";
    
    while (running && std::getline(std::cin, input)) {
        if (input == "q" || input == "quit") {
            break;
        } else if (input == "h" || input == "help") {
            printHelp();
        } else if (input == "s" || input == "stats") {
            stats.printStats();
        } else if (input == "w" || input == "watch") {
            watchRules.printWatchedItems();
        } else if (input == "a" || input == "anomalies") {
            anomalyDetector.printStats();
        } else if (input == "r" || input == "reset") {
            stats.reset();
            anomalyDetector.reset();
            std::cout << Utils::Colors::GREEN << "Statistics reset" << Utils::Colors::RESET << std::endl;
        } else if (input.substr(0, 2) == "l " || input.substr(0, 4) == "log ") {
            std::string filename = input.substr(input.find(' ') + 1);
            if (filename == "off") {
                logger.disableLogging();
            } else {
                logger.enableLogging(filename);
            }
        } else if (input.substr(0, 2) == "e " || input.substr(0, 7) == "export ") {
            std::string filename = input.substr(input.find(' ') + 1);
            std::vector<PacketInfo> packets(recentPackets, 
                                          recentPackets + (std::min)(stats.getTotalPackets(), 
                                                                  static_cast<uint64_t>(MAX_DISPLAY_PACKETS)));
            logger.exportToCSV(packets, filename);
        } else {
            std::cout << Utils::Colors::YELLOW << "Unknown command. Type 'h' for help." 
                      << Utils::Colors::RESET << std::endl;
        }
        
        std::cout << "\nCommand: ";
    }
    
    running = false;
}
