#include "monitor.hpp"
#include "common.hpp"

#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>

TrafficMonitor::TrafficMonitor(const std::string& ifname) : ifname_(ifname) {}

void TrafficMonitor::onPacket(const PacketRecord& rec) {
    std::lock_guard<std::mutex> lock(mutex_);
    hostStats_[rec.srcIp].packets++;
    hostStats_[rec.srcIp].bytes += rec.length;
    protoStats_[rec.proto].packets++;
    protoStats_[rec.proto].bytes += rec.length;
    totalPackets_++;
    totalBytes_ += rec.length;
}

static const char* protoLabel(TransportProto p) {
    switch (p) {
        case TransportProto::TCP: return "TCP";
        case TransportProto::UDP: return "UDP";
        case TransportProto::ICMP: return "ICMP";
        default: return "OTHER";
    }
}

void TrafficMonitor::render() const {
    std::cout << "\033[2J\033[H";
    std::cout << "LAN Traffic Monitor — interface: " << ifname_ << "\n";
    std::cout << "Total packets: " << totalPackets_
               << "   Total traffic: " << humanBytes(totalBytes_) << "\n\n";

    std::cout << "By protocol:\n";
    std::cout << std::left << std::setw(10) << "PROTO"
               << std::setw(12) << "PACKETS" << "BYTES\n";
    for (const auto& [proto, stats] : protoStats_) {
        std::cout << std::left << std::setw(10) << protoLabel(proto)
                   << std::setw(12) << stats.packets << humanBytes(stats.bytes) << "\n";
    }

    std::cout << "\nTop talkers:\n";
    std::cout << std::left << std::setw(18) << "SOURCE IP"
               << std::setw(12) << "PACKETS" << "BYTES\n";

    std::vector<std::pair<std::string, HostStats>> hosts(hostStats_.begin(), hostStats_.end());
    std::sort(hosts.begin(), hosts.end(), [](const auto& a, const auto& b) {
        return a.second.bytes > b.second.bytes;
    });

    int shown = 0;
    for (const auto& [ip, stats] : hosts) {
        if (shown++ >= 10) break;
        std::cout << std::left << std::setw(18) << ip
                   << std::setw(12) << stats.packets << humanBytes(stats.bytes) << "\n";
    }

    std::cout << "\nPress Ctrl+C to stop.\n";
}

void TrafficMonitor::run(int refreshSeconds) {
    running_ = true;
    PacketManager pm(ifname_);
    if (!pm.open("")) return;

    std::thread captureThread([&pm, this]() {
        pm.startCapture([this](const PacketRecord& rec) { onPacket(rec); }, 0);
    });

    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(refreshSeconds));
        std::lock_guard<std::mutex> lock(mutex_);
        render();
    }

    pm.stop();
    if (captureThread.joinable()) captureThread.join();
}

void TrafficMonitor::stop() {
    running_ = false;
}
