#include "scanner.hpp"

#include <cstring>
#include <chrono>
#include <thread>
#include <map>
#include <iostream>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <pcap.h>

struct ArpPacket {
    struct ether_header eth;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t senderMac[6];
    uint32_t senderIp;
    uint8_t targetMac[6];
    uint32_t targetIp;
} __attribute__((packed));

NetworkScanner::NetworkScanner(const InterfaceInfo& iface) : iface_(iface) {}

void NetworkScanner::sendArpRequest(int rawSock, uint32_t targetIp) {
    ArpPacket pkt{};

    std::memset(pkt.eth.ether_dhost, 0xFF, 6);
    std::memcpy(pkt.eth.ether_shost, iface_.mac.data(), 6);
    pkt.eth.ether_type = htons(ETHERTYPE_ARP);

    pkt.htype = htons(1);
    pkt.ptype = htons(ETHERTYPE_IP);
    pkt.hlen = 6;
    pkt.plen = 4;
    pkt.opcode = htons(ARPOP_REQUEST);

    std::memcpy(pkt.senderMac, iface_.mac.data(), 6);
    pkt.senderIp = htonl(ipStringToInt(iface_.ipv4));
    std::memset(pkt.targetMac, 0x00, 6);
    pkt.targetIp = htonl(targetIp);

    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = iface_.ifindex;
    sll.sll_halen = 6;
    std::memset(sll.sll_addr, 0xFF, 6);

    sendto(rawSock, &pkt, sizeof(pkt), 0,
           reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll));
}

std::vector<ScanResult> NetworkScanner::scanSubnet(int timeoutMs) {
    std::vector<ScanResult> results;

    int rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (rawSock < 0) {
        std::cerr << "Failed to open raw socket, run with sudo\n";
        return results;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface_.name.c_str(), 65536, 1, 10, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        close(rawSock);
        return results;
    }

    struct bpf_program filter{};
    if (pcap_compile(handle, &filter, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    uint32_t ipHost = ipStringToInt(iface_.ipv4);
    uint32_t maskHost = ipStringToInt(iface_.netmask);
    uint32_t network = ipHost & maskHost;
    uint32_t broadcast = network | (~maskHost);

    std::map<std::string, ScanResult> found;
    auto start = std::chrono::steady_clock::now();

    for (uint32_t target = network + 1; target < broadcast; target++) {
        sendArpRequest(rawSock, target);
    }

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeoutMs) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int rc = pcap_next_ex(handle, &header, &data);
        if (rc <= 0) continue;

        const auto* eth = reinterpret_cast<const struct ether_header*>(data);
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;

        const auto* arp = reinterpret_cast<const ArpPacket*>(data);
        if (ntohs(arp->opcode) != ARPOP_REPLY) continue;

        std::string ip = ipIntToString(ntohl(arp->senderIp));
        std::string mac = macToString(arp->senderMac);

        if (found.find(ip) == found.end()) {
            ScanResult r;
            r.ip = ip;
            r.mac = mac;
            r.responseMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            found[ip] = r;
        }
    }

    pcap_close(handle);
    close(rawSock);

    for (auto& [ip, r] : found) {
        results.push_back(r);
    }
    return results;
}
