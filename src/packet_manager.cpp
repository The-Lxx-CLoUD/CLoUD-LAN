#include "packet_manager.hpp"
#include "common.hpp"

#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

PacketManager::PacketManager(const std::string& ifname) : ifname_(ifname) {}

PacketManager::~PacketManager() {
    stop();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketManager::open(const std::string& bpfFilter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(ifname_.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return false;
    }

    if (!bpfFilter.empty()) {
        struct bpf_program prog{};
        if (pcap_compile(handle_, &prog, bpfFilter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            std::cerr << "Invalid filter: " << pcap_geterr(handle_) << "\n";
            return false;
        }
        if (pcap_setfilter(handle_, &prog) != 0) {
            std::cerr << "Failed to apply filter: " << pcap_geterr(handle_) << "\n";
            pcap_freecode(&prog);
            return false;
        }
        pcap_freecode(&prog);
    }

    return true;
}

static std::string nowTimestamp() {
    char buf[32];
    time_t t = time(nullptr);
    struct tm tmVal{};
    localtime_r(&t, &tmVal);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmVal);
    return std::string(buf);
}

void PacketManager::pcapCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
    auto* self = reinterpret_cast<PacketManager*>(user);
    self->handlePacket(header, bytes);
}

void PacketManager::handlePacket(const struct pcap_pkthdr* header, const u_char* bytes) {
    if (header->caplen < sizeof(struct ether_header)) return;

    const auto* eth = reinterpret_cast<const struct ether_header*>(bytes);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const auto* ip = reinterpret_cast<const struct ip*>(bytes + sizeof(struct ether_header));
    int ipHeaderLen = ip->ip_hl * 4;

    PacketRecord rec;
    rec.id = nextId_++;
    rec.timestamp = nowTimestamp();
    rec.srcIp = inet_ntoa(ip->ip_src);
    rec.dstIp = inet_ntoa(ip->ip_dst);
    rec.length = header->len;

    const u_char* transportStart = bytes + sizeof(struct ether_header) + ipHeaderLen;
    bool haveTransport = header->caplen >= static_cast<uint32_t>(
        sizeof(struct ether_header) + ipHeaderLen + 4);

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            rec.proto = TransportProto::TCP;
            if (haveTransport) {
                rec.srcPort = ntohs(*reinterpret_cast<const uint16_t*>(transportStart));
                rec.dstPort = ntohs(*reinterpret_cast<const uint16_t*>(transportStart + 2));
            }
            break;
        case IPPROTO_UDP:
            rec.proto = TransportProto::UDP;
            if (haveTransport) {
                rec.srcPort = ntohs(*reinterpret_cast<const uint16_t*>(transportStart));
                rec.dstPort = ntohs(*reinterpret_cast<const uint16_t*>(transportStart + 2));
            }
            break;
        case IPPROTO_ICMP:
            rec.proto = TransportProto::ICMP;
            break;
        default:
            rec.proto = TransportProto::OTHER;
            break;
    }

    history_.push_back(rec);
    if (userCallback_) userCallback_(rec);
}

void PacketManager::startCapture(PacketCallback callback, int maxPackets) {
    if (!handle_) return;
    userCallback_ = std::move(callback);
    running_ = true;
    pcap_loop(handle_, maxPackets, &PacketManager::pcapCallback, reinterpret_cast<u_char*>(this));
}

void PacketManager::stop() {
    if (running_ && handle_) {
        pcap_breakloop(handle_);
    }
    running_ = false;
}

static const char* protoName(TransportProto p) {
    switch (p) {
        case TransportProto::TCP: return "TCP";
        case TransportProto::UDP: return "UDP";
        case TransportProto::ICMP: return "ICMP";
        default: return "OTHER";
    }
}

bool PacketManager::saveLogToFile(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;

    out << "id,time,proto,src,sport,dst,dport,length\n";
    for (const auto& r : history_) {
        out << r.id << "," << r.timestamp << "," << protoName(r.proto) << ","
            << r.srcIp << "," << r.srcPort << "," << r.dstIp << "," << r.dstPort
            << "," << r.length << "\n";
    }
    return true;
}
