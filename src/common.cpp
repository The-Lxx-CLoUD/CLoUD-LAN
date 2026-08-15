#include "common.hpp"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bool getInterfaceInfo(const std::string& ifname, InterfaceInfo& out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    out.name = ifname;

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
        out.ifindex = ifr.ifr_ifindex;
    }

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        out.ipv4 = inet_ntoa(addr->sin_addr);
    }

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
        out.netmask = inet_ntoa(addr->sin_addr);
    }

    if (ioctl(fd, SIOCGIFBRDADDR, &ifr) == 0) {
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_broadaddr);
        out.broadcast = inet_ntoa(addr->sin_addr);
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        std::memcpy(out.mac.data(), ifr.ifr_hwaddr.sa_data, 6);
    }

    close(fd);
    return !out.ipv4.empty();
}

std::string macToString(const uint8_t* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

uint32_t ipStringToInt(const std::string& ip) {
    struct in_addr addr{};
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

std::string ipIntToString(uint32_t ip) {
    struct in_addr addr{};
    addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(addr));
}

uint16_t checksum16(const void* data, size_t len) {
    const uint16_t* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(buf);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

std::string humanBytes(uint64_t bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double val = static_cast<double>(bytes);
    int unit = 0;
    while (val >= 1024.0 && unit < 4) {
        val /= 1024.0;
        unit++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(unit == 0 ? 0 : 2) << val << " " << units[unit];
    return oss.str();
}

bool isRunningAsRoot() {
    return geteuid() == 0;
}
