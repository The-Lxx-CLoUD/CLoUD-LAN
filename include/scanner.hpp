#pragma once

#include <string>
#include <vector>
#include "common.hpp"

struct ScanResult {
    std::string ip;
    std::string mac;
    double responseMs = 0.0;
};

class NetworkScanner {
public:
    explicit NetworkScanner(const InterfaceInfo& iface);
    std::vector<ScanResult> scanSubnet(int timeoutMs = 800);

private:
    InterfaceInfo iface_;
    void sendArpRequest(int rawSock, uint32_t targetIp);
};
