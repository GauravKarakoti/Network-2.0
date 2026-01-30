#include "Logger.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>

Logger::Logger() : isLoggingEnabled(false) {}

Logger::~Logger() {
    disableLogging();
}

void Logger::writeCSVHeader() {
    if (csvFile.is_open()) {
        csvFile << "Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Source_MAC,Dest_MAC,Protocol,Size_Bytes,Is_Anomaly,Anomaly_Reason" << std::endl;
    }
}

bool Logger::enableLogging(const std::string& filename) {
    if (csvFile.is_open()) {
        csvFile.close();
    }
    
    csvFilename = filename;
    csvFile.open(filename, std::ios::out | std::ios::trunc);
    
    if (csvFile.is_open()) {
        isLoggingEnabled = true;
        writeCSVHeader();
        std::cout << Utils::Colors::GREEN << "Logging enabled: " << filename << Utils::Colors::RESET << std::endl;
        return true;
    }
    
    std::cout << Utils::Colors::RED << "Failed to open log file: " << filename << Utils::Colors::RESET << std::endl;
    return false;
}

void Logger::disableLogging() {
    if (csvFile.is_open()) {
        csvFile.close();
    }
    isLoggingEnabled = false;
    std::cout << Utils::Colors::YELLOW << "Logging disabled" << Utils::Colors::RESET << std::endl;
}

void Logger::logPacket(const PacketInfo& packet) {
    if (!isLoggingEnabled || !csvFile.is_open()) return;
    
    csvFile << Utils::formatTimestamp(packet.timestamp) << ","
            << packet.sourceIP << ","
            << packet.sourcePort << ","
            << packet.destIP << ","
            << packet.destPort << ","
            << packet.sourceMAC << ","
            << packet.destMAC << ","
            << packet.protocol << ","
            << packet.packetSize << ","
            << (packet.isAnomaly ? "true" : "false") << ","
            << "\"" << packet.anomalyReason << "\""
            << std::endl;
}

void Logger::logAlert(const Alert& alert) {
    if (!isLoggingEnabled || !csvFile.is_open()) return;
    
    const auto& packet = alert.packet;
    csvFile << Utils::formatTimestamp(alert.timestamp) << ","
            << packet.sourceIP << ","
            << packet.sourcePort << ","
            << packet.destIP << ","
            << packet.destPort << ","
            << packet.sourceMAC << ","
            << packet.destMAC << ","
            << packet.protocol << ","
            << packet.packetSize << ","
            << "true,"
            << "\"ALERT: " << alert.message << "\""
            << std::endl;
}

void Logger::exportToCSV(const std::vector<PacketInfo>& packets, const std::string& filename) {
    std::ofstream exportFile(filename);
    
    if (!exportFile.is_open()) {
        std::cout << Utils::Colors::RED << "Failed to create export file: " << filename << Utils::Colors::RESET << std::endl;
        return;
    }
    
    exportFile << "Timestamp,Source_IP,Source_Port,Dest_IP,Dest_Port,Source_MAC,Dest_MAC,Protocol,Size_Bytes,Is_Anomaly,Anomaly_Reason" << std::endl;
    
    for (const auto& packet : packets) {
        exportFile << Utils::formatTimestamp(packet.timestamp) << ","
                   << packet.sourceIP << ","
                   << packet.sourcePort << ","
                   << packet.destIP << ","
                   << packet.destPort << ","
                   << packet.sourceMAC << ","
                   << packet.destMAC << ","
                   << packet.protocol << ","
                   << packet.packetSize << ","
                   << (packet.isAnomaly ? "true" : "false") << ","
                   << "\"" << packet.anomalyReason << "\""
                   << std::endl;
    }
    
    exportFile.close();
    std::cout << Utils::Colors::GREEN << "Exported " << packets.size() << " packets to " << filename << Utils::Colors::RESET << std::endl;
}
