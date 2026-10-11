#pragma once
#include <arpa/inet.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
namespace bifrost_owner {
static void owner_require(bool ok, const char* code) { if (!ok) throw std::runtime_error(code); }
static std::string proc_endpoint(const std::string& host, unsigned port, bool& v6) {
    unsigned char address[16]{};
    v6 = host.find(':') != std::string::npos;
    owner_require(port <= 65535 && inet_pton(v6 ? AF_INET6 : AF_INET, host.c_str(), address) == 1, "BF-ROOT-OWNER");
    std::string encoded; char part[16];
    for (int word = 0; word < (v6 ? 4 : 1); ++word)
        for (int byte = 3; byte >= 0; --byte) {
            snprintf(part, sizeof(part), "%02X", address[word * 4 + byte]); encoded += part;
        }
    snprintf(part, sizeof(part), ":%04X", port); return encoded + part;
}
static std::string connection_owner(const std::string& line) {
    std::istringstream query(line); std::string op, source, target, extra;
    unsigned protocol, source_port, target_port;
    owner_require(bool(query >> op >> protocol >> source >> source_port >> target >> target_port) && !(query >> extra) &&
        (protocol == 6 || protocol == 17), "BF-ROOT-OWNER");
    bool v6, target_v6;
    auto local = proc_endpoint(source, source_port, v6), remote = proc_endpoint(target, target_port, target_v6);
    owner_require(v6 == target_v6, "BF-ROOT-OWNER");
    unsigned result = 0; bool found = false;
    for (int pass = 0; pass < (v6 ? 1 : 2); ++pass) {
        bool table_v6 = v6 || pass == 1;
        std::string zero(table_v6 ? 32 : 8, '0');
        std::string a_expected = local, b_expected = remote;
        if (!v6 && table_v6) {
            a_expected = "0000000000000000FFFF0000" + local;
            b_expected = "0000000000000000FFFF0000" + remote;
        }
        std::ifstream sockets("/proc/net/" + std::string(protocol == 6 ? "tcp" : "udp") + (table_v6 ? "6" : ""));
        std::string row; std::getline(sockets, row);
        while (std::getline(sockets, row)) {
            std::istringstream fields(row); std::string index, a, b, state, queue, timer, retrans; unsigned uid;
            if (!(fields >> index >> a >> b >> state >> queue >> timer >> retrans >> uid)) continue;
            if (a != a_expected && !(protocol == 17 && a == zero + local.substr(local.find(':')))) continue;
            if (b != b_expected && !(protocol == 17 && b == zero + ":0000")) continue;
            owner_require(!found || result == uid, "BF-ROOT-OWNER");
            found = true; result = uid;
        }
    }
    owner_require(found, "BF-OWNER-NOT-FOUND"); return "UID " + std::to_string(result);
}
}
