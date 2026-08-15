#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <iomanip>

#include <pcap.h>

#include "common.hpp"
#include "scanner.hpp"
#include "packet_manager.hpp"
#include "monitor.hpp"

static TrafficMonitor* g_activeMonitor = nullptr;

void handleSigint(int) {
    if (g_activeMonitor) g_activeMonitor->stop();
}

std::vector<std::string> listInterfaces() {
    std::vector<std::string> names;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        std::cerr << "pcap_findalldevs failed: " << errbuf << "\n";
        return names;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        names.emplace_back(d->name);
    }
    pcap_freealldevs(alldevs);
    return names;
}

std::string chooseInterface() {
    auto ifaces = listInterfaces();
    if (ifaces.empty()) {
        std::cerr << "No network interfaces found.\n";
        return "";
    }

    std::cout << "Available interfaces:\n";
    for (size_t i = 0; i < ifaces.size(); i++) {
        std::cout << "  " << i + 1 << ") " << ifaces[i] << "\n";
    }

    std::cout << "Select interface [1-" << ifaces.size() << "]: ";
    size_t choice = 0;
    std::cin >> choice;
    std::cin.ignore();

    if (choice < 1 || choice > ifaces.size()) {
        std::cerr << "Invalid selection.\n";
        return "";
    }
    return ifaces[choice - 1];
}

void runScanner(const InterfaceInfo& iface) {
    NetworkScanner scanner(iface);
    std::cout << "Scanning " << iface.ipv4 << "/" << iface.netmask << " ...\n";

    auto results = scanner.scanSubnet(1500);

    std::cout << "\nDiscovered " << results.size() << " host(s):\n";
    std::cout << std::left << std::setw(18) << "IP" << std::setw(20) << "MAC"
               << "RESPONSE (ms)\n";
    for (const auto& r : results) {
        std::cout << std::left << std::setw(18) << r.ip
                   << std::setw(20) << r.mac << r.responseMs << "\n";
    }
}

void runPacketManager(const std::string& ifname) {
    std::cout << "Optional BPF filter (e.g. 'tcp port 80', empty for none): ";
    std::string filter;
    std::getline(std::cin, filter);

    std::cout << "Number of packets to capture (0 = until Ctrl+C): ";
    int maxPackets = 0;
    std::cin >> maxPackets;
    std::cin.ignore();

    PacketManager pm(ifname);
    if (!pm.open(filter)) return;

    std::cout << "Capturing... press Ctrl+C to stop early.\n";

    pm.startCapture([](const PacketRecord& rec) {
        const char* protoStr =
            rec.proto == TransportProto::TCP ? "TCP" :
            rec.proto == TransportProto::UDP ? "UDP" :
            rec.proto == TransportProto::ICMP ? "ICMP" : "OTHER";

        std::cout << "[" << rec.timestamp << "] " << protoStr << "  "
                  << rec.srcIp << ":" << rec.srcPort << " -> "
                  << rec.dstIp << ":" << rec.dstPort
                  << "  (" << rec.length << " bytes)\n";
    }, maxPackets);

    std::cout << "\nSave capture log to file? (y/n): ";
    char save;
    std::cin >> save;
    std::cin.ignore();

    if (save == 'y' || save == 'Y') {
        std::cout << "File path: ";
        std::string path;
        std::getline(std::cin, path);
        if (pm.saveLogToFile(path)) {
            std::cout << "Saved " << pm.history().size() << " records to " << path << "\n";
        } else {
            std::cerr << "Failed to write file.\n";
        }
    }
}

void runMonitor(const std::string& ifname) {
    TrafficMonitor monitor(ifname);
    g_activeMonitor = &monitor;
    std::signal(SIGINT, handleSigint);
    monitor.run(1);
    g_activeMonitor = nullptr;
    std::signal(SIGINT, SIG_DFL);
}

int main() {
    if (!isRunningAsRoot()) {
        std::cerr << "Warning: raw packet capture usually requires root privileges.\n";
        std::cerr << "Re-run with sudo if you hit permission errors.\n\n";
    }

    while (true) {
        std::cout << "\n=== LAN Toolkit ===\n";
        std::cout << "\n⚠️ dev : LxxCLoUD --> Telegram : https://t.me/lxxcloud ⚠️\n";
        std::cout << "1) Scan local network (ARP discovery)\n";
        std::cout << "2) Packet manager (capture, filter, log)\n";
        std::cout << "3) Live traffic monitor\n";
        std::cout << "4) Exit\n";
        std::cout << "Choice: ";

        int choice = 0;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 4) break;

        std::string ifname = chooseInterface();
        if (ifname.empty()) continue;

        if (choice == 1) {
            InterfaceInfo info;
            if (!getInterfaceInfo(ifname, info)) {
                std::cerr << "Could not read interface info (needs an IPv4 address).\n";
                continue;
            }
            runScanner(info);
        } else if (choice == 2) {
            runPacketManager(ifname);
        } else if (choice == 3) {
            runMonitor(ifname);
        } else {
            std::cerr << "Invalid choice.\n";
        }
    }

    std::cout << "Bye.\n";
    return 0;
}
