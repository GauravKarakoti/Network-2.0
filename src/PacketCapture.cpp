#include "PacketCapture.h"
#include "Utils.h"
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

PacketCapture::PacketCapture() : handle(nullptr), isCapturing(false), onPacketReceived(nullptr) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

PacketCapture::~PacketCapture() {
    stopCapture();
#ifdef _WIN32
    WSACleanup();
#endif
}

std::vector<std::string> PacketCapture::getAvailableInterfaces() {
    std::vector<std::string> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << Utils::Colors::RED << "Error finding devices: " << errbuf 
                  << Utils::Colors::RESET << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t* device = alldevs; device != nullptr; device = device->next) {
        interfaces.push_back(device->name);
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

bool PacketCapture::initialize(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (iface.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cout << Utils::Colors::RED << "Error finding devices: " << errbuf 
                      << Utils::Colors::RESET << std::endl;
            return false;
        }
        
        if (alldevs == nullptr) {
            std::cout << Utils::Colors::RED << "No network interfaces found" 
                      << Utils::Colors::RESET << std::endl;
            return false;
        }
        
        interface = alldevs->name;
        pcap_freealldevs(alldevs);
    } else {
        interface = iface;
    }
    
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cout << Utils::Colors::RED << "Error opening interface " << interface 
                  << ": " << errbuf << Utils::Colors::RESET << std::endl;
        return false;
    }
    
    std::cout << Utils::Colors::GREEN << "Initialized capture on interface: " 
              << interface << Utils::Colors::RESET << std::endl;
    return true;
}

bool PacketCapture::startCapture() {
    if (handle == nullptr) {
        std::cout << Utils::Colors::RED << "Capture not initialized" << Utils::Colors::RESET << std::endl;
        return false;
    }
    
    isCapturing = true;
    std::cout << Utils::Colors::GREEN << "Starting packet capture..." << Utils::Colors::RESET << std::endl;
    
    if (pcap_loop(handle, -1, packetHandler, reinterpret_cast<u_char*>(this)) == -1) {
        std::cout << Utils::Colors::RED << "Error in packet capture loop: " 
                  << pcap_geterr(handle) << Utils::Colors::RESET << std::endl;
        return false;
    }
    
    return true;
}

void PacketCapture::stopCapture() {
    if (handle != nullptr) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }
    isCapturing = false;
    std::cout << Utils::Colors::YELLOW << "Packet capture stopped" << Utils::Colors::RESET << std::endl;
}

void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    
    if (capture->onPacketReceived) {
        PacketInfo info = capture->parsePacket(pkthdr, packet);
        capture->onPacketReceived(info);
    }
}

PacketInfo PacketCapture::parsePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    info.packetSize = pkthdr->len;
    info.timestamp = std::chrono::system_clock::now();
    
    // Extract MAC addresses from Ethernet header (first 14 bytes)
    // Ethernet header: 6 bytes dest MAC + 6 bytes source MAC + 2 bytes EtherType
    info.destMAC = Utils::macToString(packet);          // Bytes 0-5
    info.sourceMAC = Utils::macToString(packet + 6);    // Bytes 6-11
    
    const u_char* ip_packet = packet + 14;
    
#ifdef _WIN32
    struct ip {
        unsigned char ip_hl:4;
        unsigned char ip_v:4;
        unsigned char ip_tos;
        unsigned short ip_len;
        unsigned short ip_id;
        unsigned short ip_off;
        unsigned char ip_ttl;
        unsigned char ip_p;
        unsigned short ip_sum;
        struct in_addr ip_src;
        struct in_addr ip_dst;
    };
#endif
    
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_packet);
  
    info.sourceIP = ipToString(ntohl(ip_header->ip_src.s_addr));
    info.destIP = ipToString(ntohl(ip_header->ip_dst.s_addr));
    info.protocol = Utils::protocolToString(ip_header->ip_p);
    
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        const u_char* transport_header = ip_packet + (ip_header->ip_hl * 4);
        
        struct transport_ports {
            uint16_t source;
            uint16_t dest;
        };
        
        const struct transport_ports* ports = 
            reinterpret_cast<const struct transport_ports*>(transport_header);
        
        info.sourcePort = ntohs(ports->source);
        info.destPort = ntohs(ports->dest);
    }
    
    return info;
}

std::string PacketCapture::ipToString(uint32_t ip) {
    char buffer[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    
    if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) != nullptr) {
        return std::string(buffer);
    }
    return "0.0.0.0";
}
