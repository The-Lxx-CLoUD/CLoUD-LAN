#pragma once

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include "packet_manager.hpp"

struct HostStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

struct ProtoStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

class TrafficMonitor {
public:
    explicit TrafficMonitor(const std::string& ifname);
    void run(int refreshSeconds = 1);
    void stop();

private:
    std::string ifname_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;

    std::map<std::string, HostStats> hostStats_;
    std::map<TransportProto, ProtoStats> protoStats_;
    uint64_t totalPackets_ = 0;
    uint64_t totalBytes_ = 0;

    void onPacket(const PacketRecord& rec);
    void render() const;
};
