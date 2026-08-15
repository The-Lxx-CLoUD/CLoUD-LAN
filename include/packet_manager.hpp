#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <pcap.h>

enum class TransportProto { TCP, UDP, ICMP, OTHER };

struct PacketRecord {
    uint64_t id = 0;
    std::string timestamp;
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    TransportProto proto = TransportProto::OTHER;
    uint32_t length = 0;
};

class PacketManager {
public:
    using PacketCallback = std::function<void(const PacketRecord&)>;

    explicit PacketManager(const std::string& ifname);
    ~PacketManager();

    bool open(const std::string& bpfFilter = "");
    void startCapture(PacketCallback callback, int maxPackets = 0);
    void stop();

    bool saveLogToFile(const std::string& path) const;
    const std::vector<PacketRecord>& history() const { return history_; }

private:
    std::string ifname_;
    pcap_t* handle_ = nullptr;
    std::atomic<bool> running_{false};
    uint64_t nextId_ = 1;
    std::vector<PacketRecord> history_;

    static void pcapCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes);
    void handlePacket(const struct pcap_pkthdr* header, const u_char* bytes);

    PacketCallback userCallback_;
};
