#pragma once

#include <string>
#include <cstdint>
#include <array>
#include <net/if.h>

struct InterfaceInfo {
    std::string name;
    std::string ipv4;
    std::string netmask;
    std::string broadcast;
    std::array<uint8_t, 6> mac{};
    int ifindex = -1;
};

bool getInterfaceInfo(const std::string& ifname, InterfaceInfo& out);
std::string macToString(const uint8_t* mac);
uint32_t ipStringToInt(const std::string& ip);
std::string ipIntToString(uint32_t ip);
uint16_t checksum16(const void* data, size_t len);
std::string humanBytes(uint64_t bytes);
bool isRunningAsRoot();
