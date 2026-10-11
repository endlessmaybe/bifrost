// Bifrost's privileged boundary owns only a TUN, exact UID rules, and one filter
// chain. The unprivileged app retains keys and account checks; the independent
// Root daemon owns the core and the authenticated boundary socket.
// Closing the authenticated local socket releases the boundary, including when
// the application is replaced or removed. No boot hook or SELinux changes.
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <ifaddrs.h>
#include <linux/if_tun.h>
#include <map>
#include <net/if.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using Args = std::vector<std::string>;
static volatile sig_atomic_t quitting = 0;
static void signal_stop(int) { quitting = 1; }
static void require(bool ok, const char* code) { if (!ok) throw std::runtime_error(code); }
static std::string number(unsigned value) { return std::to_string(value); }
static int command(const Args& args, std::string* output = nullptr) {
    int pipes[2]; require(pipe2(pipes, O_CLOEXEC) == 0, "BF-ROOT-PIPE");
    pid_t child = fork(); require(child >= 0, "BF-ROOT-FORK");
    if (child == 0) {
        dup2(pipes[1], STDOUT_FILENO); dup2(pipes[1], STDERR_FILENO);
        close(pipes[0]); close(pipes[1]);
        std::vector<char*> argv;
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr); execv(argv[0], argv.data()); _exit(127);
    }
    close(pipes[1]);
    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    std::string text; int status = 0; bool finished = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        char bytes[1024]; ssize_t count;
        while ((count = read(pipes[0], bytes, sizeof(bytes))) > 0) {
            if (text.size() < 65536) text.append(bytes, std::min<size_t>(count, 65536 - text.size()));
        }
        if (waitpid(child, &status, WNOHANG) == child) { finished = true; break; }
        pollfd wait{pipes[0], POLLIN, 0}; poll(&wait, 1, 25);
        // A child can close stdout before waitpid reports its exit. POLLHUP
        // remains immediately readable; do not mistake 200 busy iterations
        // for a five-second timeout and kill a successfully finishing command.
        if (wait.revents & POLLHUP) poll(nullptr, 0, 5);
    }
    if (!finished) { kill(child, SIGKILL); waitpid(child, &status, 0); }
    char bytes[1024]; ssize_t count;
    while ((count = read(pipes[0], bytes, sizeof(bytes))) > 0)
        if (text.size() < 65536) text.append(bytes, std::min<size_t>(count, 65536 - text.size()));
    close(pipes[0]); if (output) *output = text;
    return finished && WIFEXITED(status) ? WEXITSTATUS(status) : 124;
}
static void run(const Args& args) { require(command(args) == 0, "BF-ROOT-COMMAND"); }
static std::string read_line(int socket, int timeout_seconds = 30) {
    std::string line;
    while (!quitting && line.size() < 8192) {
        pollfd p{socket, POLLIN, 0};
        int ready = poll(&p, 1, timeout_seconds * 1000);
        if (ready < 0 && errno == EINTR) continue;
        require(ready > 0, "BF-ROOT-SOCKET");
        char ch; require(read(socket, &ch, 1) == 1, "BF-ROOT-EOF");
        if (ch == '\n') return line;
        require(ch >= 32 && ch <= 126, "BF-ROOT-PROTOCOL");
        line.push_back(ch);
    }
    throw std::runtime_error("BF-ROOT-PROTOCOL");
}
static void reply(int socket, const std::string& text) {
    std::string bytes = text + "\n"; size_t offset = 0;
    while (offset < bytes.size()) {
        auto count = send(socket, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
        require(count > 0, "BF-ROOT-EOF"); offset += count;
    }
}
#include "bifrost_connection_owner.h"
using bifrost_owner::connection_owner;
#include "bifrost_root_mark.h"

struct Policy {
    unsigned owner = 0;
    bool protected_mark = false;
    bool dedicated_mark = false;
    bool local_dns = false;
    bool owner_fake_ip = false;
    bool coexist_dns = false;
    bool physical_dns = false;
    bool coexist_https = false;
    bool physical_dns_tproxy = false;
    bool split_dns = false;
    bool dns4_tproxy = false;
    bool local_origin = false;
    std::string hotspot_mode = "smart";
    std::map<std::string, int> dns_servers;
    std::string mode, wire;
    std::vector<unsigned> uids;
    std::vector<unsigned> bypass_uids;
    std::vector<std::string> ranges;
    static Policy parse(const std::string& line, unsigned expected) {
        Policy p; p.wire = line;
        std::istringstream input(line); std::string version; unsigned count;
        require(bool(input >> version >> p.owner >> p.mode >> count), "BF-ROOT-POLICY");
        require((version == "BFR1" || version == "BFR2" || version == "BFR3" || version == "BFR4" || version == "BFR5" || version == "BFR6" || version == "BFR7" || (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))))) && p.owner == expected && p.owner % 100000 >= 10000 &&
            p.owner < 2000000000 && count <= 256 &&
            (p.mode == "none" || p.mode == "allow" || p.mode == "exclude"), "BF-ROOT-POLICY");
        p.protected_mark = version != "BFR1";
        p.dedicated_mark = version != "BFR1" && version != "BFR2";
        p.local_dns = version == "BFR4" || version == "BFR5" || version == "BFR6" || version == "BFR7" || (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))));
        p.owner_fake_ip = version == "BFR5" || version == "BFR6" || version == "BFR7" || (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))));
        p.coexist_dns = version == "BFR7" || (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))));
        p.physical_dns = (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))));
        p.coexist_https = version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13")));
        p.physical_dns_tproxy = (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13")));
        p.split_dns = (version == "BFR11" || (version == "BFR12" || version == "BFR13"));
        p.dns4_tproxy = (version == "BFR12" || version == "BFR13");
        p.local_origin = version == "BFR13";
        unsigned start = p.owner / 100000 * 100000, end = start + 99999;
        for (unsigned i = 0; i < count; ++i) {
            unsigned uid; require(bool(input >> uid) && uid >= start && uid <= end && uid != p.owner, "BF-ROOT-POLICY");
            p.uids.push_back(uid);
        }
        // Infrastructure UIDs are journaled independently of the user's app
        // policy. Their protected transport must never feed back into our TUN.
        if (version == "BFR6" || version == "BFR7" || (version == "BFR8" || version == "BFR9" || (version == "BFR10" || (version == "BFR11" || (version == "BFR12" || version == "BFR13"))))) {
            unsigned bypass_count;
            require(bool(input >> bypass_count) && bypass_count <= 16, "BF-ROOT-POLICY");
            for (unsigned i = 0; i < bypass_count; ++i) {
                unsigned uid;
                require(bool(input >> uid) && uid >= start + 10000 && uid <= end && uid != p.owner, "BF-ROOT-POLICY");
                p.bypass_uids.push_back(uid);
            }
            std::sort(p.bypass_uids.begin(), p.bypass_uids.end());
            p.bypass_uids.erase(std::unique(p.bypass_uids.begin(), p.bypass_uids.end()), p.bypass_uids.end());
        }
        if (p.physical_dns) {
            unsigned dns_count;
            require(bool(input >> dns_count) && dns_count <= 16 && (p.split_dns || dns_count == 0 || !p.bypass_uids.empty()), "BF-ROOT-POLICY");
            for (unsigned i = 0; i < dns_count; ++i) {
                std::string address; require(bool(input >> address), "BF-ROOT-POLICY");
                alignas(in6_addr) unsigned char bytes[16]{}; int family = address.find(':') == std::string::npos ? 4 : 6;
                require(inet_pton(family == 4 ? AF_INET : AF_INET6, address.c_str(), bytes) == 1, "BF-ROOT-POLICY");
                require(family == 4 ? (bytes[0] != 0 && bytes[0] != 127 && bytes[0] < 224) :
                    (bytes[0] != 0xff && !(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)), "BF-ROOT-POLICY");
                require(family == 4 || !IN6_IS_ADDR_UNSPECIFIED(reinterpret_cast<in6_addr*>(bytes)), "BF-ROOT-POLICY");
                require(family == 4 || !IN6_IS_ADDR_LOOPBACK(reinterpret_cast<in6_addr*>(bytes)), "BF-ROOT-POLICY");
                char normalized[INET6_ADDRSTRLEN];
                require(inet_ntop(family == 4 ? AF_INET : AF_INET6, bytes, normalized, sizeof(normalized)) != nullptr, "BF-ROOT-POLICY");
                p.dns_servers[normalized] = family;
            }
        }
        if (p.local_origin) require(bool(input >> p.hotspot_mode) && (p.hotspot_mode == "smart" || p.hotspot_mode == "direct"), "BF-ROOT-POLICY");
        std::string extra; require(!(input >> extra), "BF-ROOT-POLICY");
        std::sort(p.uids.begin(), p.uids.end());
        p.uids.erase(std::unique(p.uids.begin(), p.uids.end()), p.uids.end());
        if (p.mode == "allow") {
            require(!p.uids.empty(), "BF-ROOT-POLICY");
            for (auto uid : p.uids) if (!std::binary_search(p.bypass_uids.begin(), p.bypass_uids.end(), uid))
                p.ranges.push_back(number(uid) + "-" + number(uid));
        } else {
            auto excluded = p.mode == "exclude" ? p.uids : std::vector<unsigned>{};
            excluded.push_back(p.owner);
            excluded.insert(excluded.end(), p.bypass_uids.begin(), p.bypass_uids.end());
            std::sort(excluded.begin(), excluded.end());
            excluded.erase(std::unique(excluded.begin(), excluded.end()), excluded.end());
            unsigned next = start;
            for (auto uid : excluded) {
                if (uid > next) p.ranges.push_back(number(next) + "-" + number(uid - 1));
                next = uid + 1;
            }
            if (next <= end) p.ranges.push_back(number(next) + "-" + number(end));
        }
        return p;
    }
};
struct Boundary {
    Policy policy;
    std::string iface, table, chain, journal;
    int tun = -1;
    bool created = false;
    Boundary(Policy p, std::string state): policy(std::move(p)), journal(std::move(state)) {
        iface = "bfr" + number(policy.owner);
        table = number(30000 + policy.owner);
        chain = "BFR_" + number(policy.owner);
    }
    Args ip(int family, const Args& suffix) const {
        Args args{"/system/bin/ip", family == 4 ? "-4" : "-6"};
        args.insert(args.end(), suffix.begin(), suffix.end()); return args;
    }
    Args filter(int family, const Args& suffix) const {
        Args args{family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "filter"};
        // Old BFR1 journals predate socket marking; cleanup must remove their
        // original exact rules rather than leaving an orphaned global fence.
        for (size_t i = 0; i < suffix.size(); ++i) {
            if (!policy.protected_mark && suffix[i] == "-m" && i + 4 < suffix.size() && suffix[i + 1] == "mark") { i += 4; continue; }
            args.push_back(policy.dedicated_mark && suffix[i] == "0x20000/0x20000"
                ? BIFROST_ROOT_MARK_MATCH : suffix[i]);
        }
        return args;
    }
    Args rule(int family, const std::string& verb, const std::string& range) const {
        if (!policy.protected_mark) return ip(family, {"rule", verb, "priority", "9000", "uidrange", range, "lookup", table});
        return ip(family, [&] { Args selector{"rule", verb, "priority", "9000", "fwmark",
            policy.dedicated_mark ? BIFROST_ROOT_UNMARKED_MATCH : "0/0x20000",
            "uidrange", range, "lookup", table}; if (policy.local_origin) selector.insert(selector.begin() + 4, {"iif", "lo"}); return selector; }());
    }
    std::string dnsTable() const { return number(130000 + policy.owner); }
    static std::string fakePrefix(int family) { return family == 4 ? "198.18.0.0/15" : "fc00::/18"; }
    Args ownerFakeRule(int family, const std::string& verb) const {
        // netd can cache proxy fake-IP answers for the excluded UI process.
        // Only those synthetic destinations need the tunnel; real-address
        // bootstrap/probe sockets retain the owner's existing underlay path.
        return ip(family, {"rule", verb, "priority", "9000", "to", fakePrefix(family),
            "fwmark", BIFROST_ROOT_UNMARKED_MATCH, "uidrange", number(policy.owner) + "-" + number(policy.owner), "lookup", table});
    }
    std::vector<std::string> coexistPrefixes(int family) const {
        if (policy.bypass_uids.empty()) return {};
        // Tailnet, MagicDNS, and private subnet-router destinations return to
        // Android's own VPN/LAN selection. No second userspace proxy hop.
        return family == 4 ? std::vector<std::string>{"100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
                           : std::vector<std::string>{"fd7a:115c:a1e0::/48"};
    }
    Args coexistRoute(int family, const std::string& verb, const std::string& prefix) const {
        return ip(family, {"route", verb, "throw", prefix, "table", table});
    }
    Args ownerFakeFence(int family, const std::string& verb) const {
        return filter(family, {verb, "OUTPUT", "-d", fakePrefix(family), "-m", "owner", "--uid-owner", number(policy.owner),
            "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH, "-j", chain});
    }
    bool ownerFakeReady(int family, const std::string& rules) const {
        std::istringstream lines(rules); std::string line;
        const auto owner = "uidrange " + number(policy.owner) + "-" + number(policy.owner) + " lookup " + table;
        while (std::getline(lines, line))
            if (line.find("to " + fakePrefix(family) + " ") != std::string::npos &&
                line.find(owner) != std::string::npos &&
                (line.find("fwmark 0x0/0x1000000 ") != std::string::npos ||
                 line.find(std::string("fwmark ") + BIFROST_ROOT_UNMARKED_MATCH + " ") != std::string::npos))
                return command(ownerFakeFence(family, "-C")) == 0;
        return false;
    }
    std::map<std::string, unsigned> dnsInterfaces;
    std::map<std::string, unsigned> dns4Interfaces;
    Args dns4InterfaceRoute(const std::string& verb, const std::string& name, unsigned index) const {
        return ip(4, {"route", verb, "local", "default", "dev", name, "metric", number(10000 + index), "table", dnsTable()});
    }
    Args dns4RouteRule(const std::string& verb) const {
        // Run before vendor private-LAN bypasses, and match only our DNS mark.
        return ip(4, {"rule", verb, "priority", "99", "fwmark", "0x2000000/0x3000000", "lookup", dnsTable()});
    }
    void refreshDns4Routes() {
        if (!policy.dns4_tproxy) return;
        ifaddrs* addresses = nullptr;
        require(getifaddrs(&addresses) == 0, "BF-ROOT-INTERFACES");
        std::map<std::string, unsigned> current;
        for (auto entry = addresses; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET ||
                !(entry->ifa_flags & IFF_UP) || (entry->ifa_flags & IFF_LOOPBACK) || iface == entry->ifa_name) continue;
            current[entry->ifa_name] = if_nametoindex(entry->ifa_name);
        }
        freeifaddrs(addresses);
        for (const auto& entry : current) if (entry.second &&
            (!dns4Interfaces.count(entry.first) || dns4Interfaces.at(entry.first) != entry.second))
            run(dns4InterfaceRoute("replace", entry.first, entry.second));
        for (const auto& entry : dns4Interfaces) if (!current.count(entry.first) || current.at(entry.first) != entry.second)
            command(dns4InterfaceRoute("del", entry.first, entry.second));
        dns4Interfaces = std::move(current);
    }
    void clearDns4Routes() {
        if (!policy.dns4_tproxy) return;
        std::string routes;
        require(command(ip(4, {"route", "show", "table", dnsTable()}), &routes) == 0, "BF-ROOT-READBACK");
        std::istringstream lines(routes); std::string line;
        while (std::getline(lines, line)) {
            std::istringstream fields(line); std::string type, prefix, dev, name, field, metric;
            fields >> type >> prefix >> dev >> name;
            if (type != "local" || prefix != "default" || dev != "dev") continue;
            while (fields >> field) if (field == "metric") { fields >> metric; break; }
            if (metric.empty() || metric.find_first_not_of("0123456789") != std::string::npos) continue;
            const unsigned value = std::stoul(metric);
            if (value > 10000) command(dns4InterfaceRoute("del", name, value - 10000));
        }
        dns4Interfaces.clear();
        command(ip(4, {"route", "del", "local", "default", "dev", "lo", "table", dnsTable()}));
        command(dns4RouteRule("del"));
    }

    std::vector<std::string> dnsLocalPrefixes() const {
        std::vector<std::string> result{"fe80::/10"};
        if (policy.physical_dns_tproxy) for (const auto& entry : policy.dns_servers)
            if (entry.second == 6) result.push_back(entry.first + "/128");
        return result;
    }
    Args dnsInterfaceRoute(const std::string& verb, const std::string& name, unsigned index, const std::string& prefix = "fe80::/10") const {
        return ip(6, {"route", verb, "local", prefix, "dev", name, "metric", number(10000 + index), "table", dnsTable()});
    }
    void refreshDnsRoutes() {
        refreshDns4Routes();
        if (!policy.local_dns) return;
        // IPv6 scoped sockets carry a bound output interface. Linux rejects a
        // lo-only policy route for them, even after MARK in OUTPUT. A local
        // route associated with that interface delivers them through loopback
        // while retaining the IPv6 scope used by Android's DNS resolver.
        ifaddrs* addresses = nullptr;
        require(getifaddrs(&addresses) == 0, "BF-ROOT-INTERFACES");
        std::map<std::string, unsigned> current;
        for (auto entry = addresses; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET6 ||
                !(entry->ifa_flags & IFF_UP) || (entry->ifa_flags & IFF_LOOPBACK) || iface == entry->ifa_name) continue;
            const auto address = reinterpret_cast<sockaddr_in6*>(entry->ifa_addr);
            if (IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr)) current[entry->ifa_name] = if_nametoindex(entry->ifa_name);
        }
        freeifaddrs(addresses);
        for (const auto& entry : current) if (entry.second &&
            (!dnsInterfaces.count(entry.first) || dnsInterfaces.at(entry.first) != entry.second))
            for (const auto& prefix : dnsLocalPrefixes()) run(dnsInterfaceRoute("replace", entry.first, entry.second, prefix));
        for (const auto& entry : dnsInterfaces) if (!current.count(entry.first) || current.at(entry.first) != entry.second)
            for (const auto& prefix : dnsLocalPrefixes()) command(dnsInterfaceRoute("del", entry.first, entry.second, prefix));
        dnsInterfaces = std::move(current);
    }
    Policy updatedDnsPolicy(const std::string& line) const {
        require(policy.split_dns, "BF-ROOT-POLICY");
        std::istringstream input(line); std::string op, address;
        input >> op;
        auto next = policy;
        // A handover replaces the physical resolver set. Accumulating every
        // resolver ever seen eventually exceeds the 16-address policy limit.
        next.dns_servers.clear();
        while (input >> address) {
            unsigned char bytes[16]{};
            const int family = address.find(':') == std::string::npos ? 4 : 6;
            require(inet_pton(family == 4 ? AF_INET : AF_INET6, address.c_str(), bytes) == 1, "BF-ROOT-POLICY");
            next.dns_servers[address] = family;
        }
        require(next.dns_servers.size() <= 16, "BF-ROOT-POLICY");
        std::string wire = std::string(next.local_origin ? "BFR13 " : (next.dns4_tproxy ? "BFR12 " : "BFR11 ")) + number(next.owner) + " " + next.mode + " " + number(next.uids.size());
        for (auto uid : next.uids) wire += " " + number(uid);
        wire += " " + number(next.bypass_uids.size());
        for (auto uid : next.bypass_uids) wire += " " + number(uid);
        wire += " " + number(next.dns_servers.size());
        for (const auto& entry : next.dns_servers) wire += " " + entry.first;
        if (next.local_origin) wire += " " + next.hotspot_mode;
        return Policy::parse(wire, policy.owner);
    }
    void updateDns(const std::string& line) {
        auto next = updatedDnsPolicy(line);
        refreshDnsRoutes();
        if (next.dns_servers == policy.dns_servers) return;
        // Remove routes for retired IPv6 resolvers while the old journal still
        // owns them. Once readback confirms removal, the replacement journal
        // can safely name only the new resolver set for crash cleanup.
        for (const auto& old : policy.dns_servers) {
            if (old.second != 6 || next.dns_servers.count(old.first)) continue;
            for (const auto& iface : dnsInterfaces)
                command(dnsInterfaceRoute("del", iface.first, iface.second, old.first + "/128"));
        }
        std::string remaining;
        require(command(ip(6, {"route", "show", "table", dnsTable()}), &remaining) == 0, "BF-ROOT-READBACK");
        for (const auto& old : policy.dns_servers) if (old.second == 6 && !next.dns_servers.count(old.first))
            require(remaining.find("local " + old.first + " ") == std::string::npos &&
                remaining.find("local " + old.first + "/128 ") == std::string::npos, "BF-ROOT-READBACK");
        const auto& wire = next.wire;
        const auto temporary = journal + ".next";
        int record = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        require(record >= 0, "BF-ROOT-JOURNAL");
        const auto bytes = wire + "\n";
        bool saved = write(record, bytes.data(), bytes.size()) == ssize_t(bytes.size()) && fsync(record) == 0;
        close(record);
        require(saved && rename(temporary.c_str(), journal.c_str()) == 0, "BF-ROOT-JOURNAL");
        policy = std::move(next);
        dnsInterfaces.clear();
        refreshDnsRoutes();
    }
    void clearDnsInterfaceRoutes() {
        std::string routes;
        require(command(ip(6, {"route", "show", "table", dnsTable()}), &routes) == 0, "BF-ROOT-READBACK");
        std::istringstream lines(routes);
        std::string line;
        while (std::getline(lines, line)) {
            std::istringstream fields(line);
            std::string type, prefix, dev, name, field, metric;
            fields >> type >> prefix >> dev >> name;
            const auto prefixes = dnsLocalPrefixes();
            // ip prints IPv6 host routes without the /128 suffix.
            const auto normalized = prefix.find('/') == std::string::npos ? prefix + "/128" : prefix;
            if (type != "local" || std::find(prefixes.begin(), prefixes.end(), normalized) == prefixes.end() || dev != "dev") continue;
            while (fields >> field) if (field == "metric") { fields >> metric; break; }
            if (metric.empty() || metric.find_first_not_of("0123456789") != std::string::npos) continue;
            // The journal owns this initially empty table; remove only the
            // scoped routes with our exact prefix/metric, never flush a table.
            unsigned value = std::stoul(metric);
            if (value > 10000) command(dnsInterfaceRoute("del", name, value - 10000, normalized));
        }
        dnsInterfaces.clear();
    }
    Args dnsRule(const std::string& verb, std::string range, const std::string& protocol, int family = 6) const {
        const bool infrastructure = policy.split_dns && std::any_of(policy.bypass_uids.begin(), policy.bypass_uids.end(),
            [&](unsigned uid) { return range == number(uid) + "-" + number(uid); });
        std::replace(range.begin(), range.end(), '-', ':');
        Args result{family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "mangle", verb, "OUTPUT",
            "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH};
        if (!policy.split_dns) result.insert(result.end(), {"-d", "fe80::/10"});
        result.insert(result.end(), {"-p", protocol, "--dport", "53", "-m", "comment", "--comment", chain + "_dns",
            "-j", "MARK", "--set-xmark", infrastructure ? "0xa000000/0xa000000" : "0x2000000/0x2000000"});
        return result;
    }
    Args dnsProxyRule(const std::string& verb, const std::string& protocol, bool infrastructure = false, int family = 6) const {
        Args args{family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "mangle", verb, "PREROUTING", "-i", "lo",
            "-m", "mark", "--mark", policy.split_dns ? (infrastructure ? "0xa000000/0xb000000" : "0x2000000/0xb000000") : "0x2000000/0x3000000", "-p", protocol};
        if (protocol == "tcp") args.push_back("--syn");
        args.insert(args.end(), {"--dport", "53", "-m", "comment", "--comment", chain + "_dns", "-j", "TPROXY", "--on-ip", family == 4 ? "127.0.0.1" : "::1",
            "--on-port", family == 4 ? (infrastructure ? "15354" : "15355") : (infrastructure ? "15356" : "15353"), "--tproxy-mark", "0x2000000/0x2000000"});
        return args;
    }
    std::vector<Args> dnsProxyRules(const std::string& verb) const {
        std::vector<Args> result;
        for (const auto& protocol : {"udp", "tcp"}) {
            result.push_back(dnsProxyRule(verb, protocol));
            if (policy.dns4_tproxy) {
                result.push_back(dnsProxyRule(verb, protocol, false, 4));
                if (!policy.bypass_uids.empty()) result.push_back(dnsProxyRule(verb, protocol, true, 4));
            }
            if (policy.split_dns && !policy.bypass_uids.empty()) result.push_back(dnsProxyRule(verb, protocol, true));
        }
        return result;
    }
    Args dnsRouteRule(const std::string& verb) const {
        return ip(6, {"rule", verb, "priority", "8999", "fwmark", "0x2000000/0x3000000", "lookup", dnsTable()});
    }
    std::vector<std::string> localDnsRanges() const {
        auto result = policy.ranges;
        if (policy.physical_dns) for (auto uid : policy.bypass_uids) result.push_back(number(uid) + "-" + number(uid));
        return result;
    }
    std::vector<Args> physicalDnsFilters(int family, const std::string& verb) const {
        std::vector<Args> result;
        if (!policy.physical_dns) return result;
        if (policy.split_dns) {
            // IPv6 is handled by dnsRule/dnsProxyRules without IPv6 NAT.
            if (family == 6) return result;
            if (policy.dns4_tproxy) {
                for (const auto& range : localDnsRanges()) for (const auto& protocol : {"udp", "tcp"})
                    result.push_back(dnsRule(verb, range, protocol, 4));
                return result;
            }
            auto add = [&](std::string range, const char* port) {
                std::replace(range.begin(), range.end(), '-', ':');
                for (const auto& protocol : {"udp", "tcp"}) result.push_back({"/system/bin/iptables", "-w", "2", "-t", "nat", verb, "OUTPUT",
                    "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH,
                    "-p", protocol, "--dport", "53", "-m", "comment", "--comment", chain + "_physical_dns",
                    "-j", "DNAT", "--to-destination", std::string("127.0.0.1:") + port});
            };
            for (const auto& range : policy.ranges) add(range, "15355");
            for (auto uid : policy.bypass_uids) add(number(uid), "15354");
            return result;
        }
        // A Wi-Fi-bound socket rejects a route through another interface.
        // DNAT only the known underlay DNS endpoint to our loopback DNS
        // ingress. Conntrack restores the original reply address/port.
        for (const auto& entry : policy.dns_servers) if (entry.second == family)
            for (auto uid : policy.bypass_uids) for (const auto& protocol : {"udp", "tcp"}) {
                if (family == 6 && policy.physical_dns_tproxy) {
                    // Android kernels may omit IPv6 NAT entirely. Reuse the
                    // existing transparent DNS listener and scoped local routes.
                    result.push_back({"/system/bin/ip6tables", "-w", "2", "-t", "mangle", verb, "OUTPUT",
                        "-m", "owner", "--uid-owner", number(uid), "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH,
                        "-d", entry.first, "-p", protocol, "--dport", "53", "-m", "comment", "--comment", chain + "_physical_dns",
                        "-j", "MARK", "--set-xmark", "0x2000000/0x2000000"});
                    continue;
                }
                result.push_back({family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "nat", verb, "OUTPUT",
                    "-m", "owner", "--uid-owner", number(uid), "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH,
                    "-d", entry.first, "-p", protocol, "--dport", "53", "-m", "comment", "--comment", chain + "_physical_dns",
                    "-j", "DNAT", "--to-destination", family == 4 ? "127.0.0.1:15354" : "[::1]:15354"});
            }
        return result;
    }
    Args coexistDnsMark(int family, const std::string& verb, unsigned uid, const std::string& protocol, const std::string& port = "53") const {
        Args result{family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "mangle", verb, "OUTPUT",
            "-m", "owner", "--uid-owner", number(uid), "-m", "mark", "!", "--mark", BIFROST_ROOT_MARK_MATCH,
            "-p", protocol, "--dport", port, "-m", "comment", "--comment", chain + (port == "53" ? "_vpn_dns" : "_vpn_https"),
            "-j", "MARK", "--set-xmark", "0x4000000/0x4000000"};
        // Scoped IPv6 resolvers use the existing TPROXY route, preserving
        // the interface scope. Do not put that traffic into a default TUN.
        if (family == 6 && policy.physical_dns && port == "53") result.insert(result.begin() + 7, {"!", "-d", "fe80::/10"});
        if (((family == 6 && policy.physical_dns_tproxy) || (family == 4 && policy.dns4_tproxy)) && port == "53")
            result.insert(result.end() - 4, {"-m", "mark", "!", "--mark", "0x2000000/0x2000000"});
        return result;
    }
    Args coexistDnsRoute(int family, const std::string& verb, unsigned uid) const {
        // Android's bundled ip lacks ipproto/dport rule selectors. Mark only
        // this infrastructure UID's plain DNS sockets, retaining netd marks.
        // Private resolver destinations still take our throw routes.
        return ip(family, {"rule", verb, "priority", "8998", "fwmark", "0x4000000/0x5000000",
            "uidrange", number(uid) + "-" + number(uid), "lookup", table});
    }
    Args coexistDnsFence(int family, const std::string& verb, unsigned uid) const {
        return filter(family, {verb, "OUTPUT", "-m", "owner", "--uid-owner", number(uid),
            "-m", "mark", "--mark", "0x4000000/0x5000000", "-j", chain});
    }
    std::vector<Args> coexistDnsFilters(int family, const std::string& verb) const {
        std::vector<Args> result;
        if (policy.coexist_dns) for (auto uid : policy.bypass_uids) {
            result.push_back(coexistDnsFence(family, verb, uid));
            for (const auto& protocol : {"udp", "tcp"}) result.push_back(coexistDnsMark(family, verb, uid, protocol));
            if (policy.coexist_https) result.push_back(coexistDnsMark(family, verb, uid, "tcp", "443"));
        }
        return result;
    }
    bool present() const {
        if (policy.dns4_tproxy) {
            std::string rules;
            require(command(ip(4, {"rule", "show"}), &rules) == 0, "BF-ROOT-READBACK");
            if (rules.find("lookup " + dnsTable()) != std::string::npos) return true;
        }
        for (int family : {4, 6}) for (const auto& args : physicalDnsFilters(family, "-C"))
            if (command(args) == 0) return true;
        for (int family : {4, 6}) for (const auto& args : coexistDnsFilters(family, "-C"))
            if (command(args) == 0) return true;
        if (policy.local_dns) for (const auto& range : localDnsRanges()) for (const auto& protocol : {"udp", "tcp"})
            if (command(dnsRule("-C", range, protocol)) == 0) return true;
        if (policy.local_dns) {
            for (const auto& args : dnsProxyRules("-C")) if (command(args) == 0) return true;
            std::string rules;
            require(command(ip(6, {"rule", "show"}), &rules) == 0, "BF-ROOT-READBACK");
            if (rules.find("lookup " + dnsTable()) != std::string::npos) return true;
        }
        for (int family : {4, 6}) {
            for (auto range : policy.ranges) {
                std::replace(range.begin(), range.end(), '-', ':');
                if (command(filter(family, {"-C", "OUTPUT", "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", "0x20000/0x20000", "-j", chain})) == 0)
                    return true;
            }
            std::string text;
            require(command(ip(family, {"rule", "show"}), &text) == 0, "BF-ROOT-READBACK");
            if (text.find("lookup " + table) != std::string::npos) return true;
            if (!coexistPrefixes(family).empty()) {
                std::string routes;
                require(command(ip(family, {"route", "show", "table", table}), &routes) == 0, "BF-ROOT-READBACK");
                for (const auto& prefix : coexistPrefixes(family))
                    if (routes.find("throw " + prefix) != std::string::npos) return true;
            }
        }
        return false;
    }
    std::vector<std::string> hotspotInterfaces;
    std::string hotspotChain() const { return chain + "_HS"; }
    std::string hotspotTable() const { return number(150000 + policy.owner); }
    Args mangle(int family, const Args& suffix) const {
        Args args{family == 4 ? "/system/bin/iptables" : "/system/bin/ip6tables", "-w", "2", "-t", "mangle"};
        args.insert(args.end(), suffix.begin(), suffix.end()); return args;
    }
    static bool validHotspotInterface(const std::string& name) {
        return !name.empty() && name.size() < IFNAMSIZ && name != "lo" &&
            name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == std::string::npos;
    }
    static std::vector<std::string> parseTetherInterfaces(const std::string& rules) {
        std::vector<std::string> result;
        std::istringstream lines(rules); std::string line;
        while (std::getline(lines, line)) {
            // Android netd's tethering rule is explicitly scoped by ingress.
            // Never guess from wlan names: wlan0 can be the physical upstream.
            std::istringstream tokens(line); std::string priority, token, name;
            if (!(tokens >> priority) || priority != "21000:") continue;
            while (tokens >> token) if (token == "iif") { tokens >> name; break; }
            if (validHotspotInterface(name) && std::find(result.begin(), result.end(), name) == result.end()) result.push_back(name);
        }
        require(result.size() <= 16, "BF-ROOT-POLICY"); return result;
    }
    Args hotspotRouteRule(int family, const std::string& verb) const {
        return ip(family, {"rule", verb, "priority", "98", "fwmark", "0x10000000/0x10000000", "lookup", hotspotTable()});
    }
    Args hotspotHook(int family, const std::string& verb, const std::string& name) const {
        return mangle(family, {verb, "PREROUTING", "-i", name, "-j", hotspotChain()});
    }
    Args hotspotInput(int family, const std::string& verb, const std::string& name) const {
        return filter(family, {verb, "INPUT", "-i", name, "-m", "mark", "--mark", "0x10000000/0x10000000",
            "-m", "comment", "--comment", hotspotChain(), "-j", "ACCEPT"});
    }
    void createHotspot() {
        for (int family : {4, 6}) {
            std::string existing;
            require(command(ip(family, {"route", "show", "table", hotspotTable()}), &existing) == 0 && existing.empty(), "BF-ROOT-COLLISION");
            for (const auto& suffix : {"", "_S", "_D", "_F"}) {
                require(command(mangle(family, {"-S", hotspotChain() + suffix})) != 0, "BF-ROOT-COLLISION");
                run(mangle(family, {"-N", hotspotChain() + suffix}));
            }
            run(ip(family, {"route", "add", "local", "default", "dev", "lo", "table", hotspotTable()}));
            run(hotspotRouteRule(family, "add"));
            run(mangle(family, {"-A", hotspotChain() + "_F", "-j", "DROP"}));
            const auto smart = hotspotChain() + "_S", direct = hotspotChain() + "_D";
            for (const auto& target : {smart, direct}) {
                run(mangle(family, {"-A", target, "-p", "udp", "--dport", "67:68", "-j", "RETURN"}));
                run(mangle(family, {"-A", target, "-d", family == 4 ? "224.0.0.0/4" : "ff00::/8", "-j", "RETURN"}));
                if (family == 4) run(mangle(family, {"-A", target, "-d", "255.255.255.255/32", "-j", "RETURN"}));
                for (const auto& protocol : {"tcp", "udp"}) {
                    Args fenceRule{"-A", target, "-p", protocol};
                    if (target == direct) fenceRule.insert(fenceRule.end(), {"--dport", "53"});
                    fenceRule.insert(fenceRule.end(), {"-j", hotspotChain() + "_F"}); run(mangle(family, fenceRule));
                    run(mangle(family, {"-A", target, "-p", protocol, "--dport", "53", "-j", "TPROXY",
                        "--on-ip", family == 4 ? "127.0.0.1" : "::1", "--on-port", target == smart ? "15357" : "15358",
                        "--tproxy-mark", "0x10000000/0x10000000"}));
                }
            }
            for (const auto& protocol : {"tcp", "udp"}) run(mangle(family, {"-A", smart, "-p", protocol, "-j", "TPROXY",
                "--on-ip", family == 4 ? "127.0.0.1" : "::1", "--on-port", "15357", "--tproxy-mark", "0x10000000/0x10000000"}));
            run(mangle(family, {"-A", hotspotChain(), "-j", hotspotChain() + (policy.hotspot_mode == "smart" ? "_S" : "_D")}));
        }
        refreshHotspot();
    }
    std::map<int, std::vector<std::string>> hotspotLocalAddresses;
    void refreshHotspotLocalAddresses(bool verify) {
        ifaddrs* addresses = nullptr;
        require(getifaddrs(&addresses) == 0, "BF-ROOT-INTERFACES");
        std::map<int, std::vector<std::string>> current;
        for (auto* entry = addresses; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr) continue;
            const int af = entry->ifa_addr->sa_family;
            if (af != AF_INET && af != AF_INET6) continue;
            char text[INET6_ADDRSTRLEN];
            const void* bytes = af == AF_INET
                ? static_cast<const void*>(&reinterpret_cast<sockaddr_in*>(entry->ifa_addr)->sin_addr)
                : static_cast<const void*>(&reinterpret_cast<sockaddr_in6*>(entry->ifa_addr)->sin6_addr);
            if (!inet_ntop(af, bytes, text, sizeof(text))) continue;
            auto& values = current[af == AF_INET ? 4 : 6];
            const std::string prefix = std::string(text) + (af == AF_INET ? "/32" : "/128");
            if (std::find(values.begin(), values.end(), prefix) == values.end()) values.push_back(prefix);
        }
        freeifaddrs(addresses);
        // Xiaomi kernels need not provide xt_addrtype. Exact interface addresses
        // preserve local gateway access without depending on that module. DNS
        // interception remains ahead of these exceptions, including gateway DNS.
        for (int family : {4, 6}) {
            const auto target = hotspotChain() + "_S";
            for (const auto& prefix : current[family]) {
                const auto& old = hotspotLocalAddresses[family];
                if (std::find(old.begin(), old.end(), prefix) == old.end() ||
                    (verify && command(mangle(family, {"-C", target, "-d", prefix, "-j", "RETURN"})) != 0))
                    run(mangle(family, {"-I", target, family == 4 ? "8" : "7", "-d", prefix, "-j", "RETURN"}));
            }
            for (const auto& prefix : hotspotLocalAddresses[family])
                if (std::find(current[family].begin(), current[family].end(), prefix) == current[family].end())
                    command(mangle(family, {"-D", target, "-d", prefix, "-j", "RETURN"}));
        }
        hotspotLocalAddresses = std::move(current);
    }
    void refreshHotspot(bool verifyHooks = false) {
        if (!policy.local_origin) return;
        refreshHotspotLocalAddresses(verifyHooks);
        std::vector<std::string> current;
        for (int family : {4, 6}) {
            std::string rules; require(command(ip(family, {"rule", "show"}), &rules) == 0, "BF-ROOT-READBACK");
            for (const auto& name : parseTetherInterfaces(rules))
                if (if_nametoindex(name.c_str()) != 0 && std::find(current.begin(), current.end(), name) == current.end()) current.push_back(name);
        }
        if (!verifyHooks && current == hotspotInterfaces) return;
        for (const auto& name : current) for (int family : {4, 6}) {
            if (command(hotspotInput(family, "-C", name)) != 0) run(hotspotInput(family, "-I", name));
            if (command(hotspotHook(family, "-C", name)) != 0) run(hotspotHook(family, "-I", name));
        }
        for (const auto& name : hotspotInterfaces) if (std::find(current.begin(), current.end(), name) == current.end())
            for (int family : {4, 6}) {
                command(hotspotHook(family, "-D", name)); command(hotspotInput(family, "-D", name));
            }
        hotspotInterfaces = std::move(current);
    }
    void hotspotFence(bool enabled) {
        for (int family : {4, 6}) run(mangle(family, {"-R", hotspotChain() + "_F", "1", "-j", enabled ? "DROP" : "RETURN"}));
    }
    void setHotspotMode(const std::string& mode) {
        require(policy.local_origin && (mode == "smart" || mode == "direct"), "BF-ROOT-POLICY");
        const auto previous = policy.hotspot_mode;
        try {
            for (int family : {4, 6}) run(mangle(family, {"-R", hotspotChain(), "1", "-j", hotspotChain() + (mode == "smart" ? "_S" : "_D")}));
            policy.hotspot_mode = mode;
            require(hotspotReady(), "BF-ROOT-READBACK");
            auto wire = policy.wire.substr(0, policy.wire.find_last_of(' ') + 1) + mode;
            const auto pending = journal + ".hotspot";
            int fd = open(pending.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
            require(fd >= 0, "BF-ROOT-JOURNAL");
            auto text = wire + "\n";
            bool saved = write(fd, text.data(), text.size()) == ssize_t(text.size()) && fsync(fd) == 0;
            close(fd); require(saved && rename(pending.c_str(), journal.c_str()) == 0, "BF-ROOT-JOURNAL");
            policy.wire = wire;
        } catch (...) {
            policy.hotspot_mode = previous;
            for (int family : {4, 6}) command(mangle(family, {"-R", hotspotChain(), "1", "-j", hotspotChain() + (previous == "smart" ? "_S" : "_D")}));
            throw;
        }
    }
    bool hotspotReady() const {
        for (int family : {4, 6}) {
            if (command(mangle(family, {"-C", hotspotChain(), "-j", hotspotChain() + (policy.hotspot_mode == "smart" ? "_S" : "_D")})) != 0) return false;
            std::string routes, rules;
            if (command(ip(family, {"route", "show", "table", hotspotTable()}), &routes) != 0 || routes.find("local default dev lo") == std::string::npos ||
                command(ip(family, {"rule", "show"}), &rules) != 0 || rules.find("98:") == std::string::npos || rules.find("lookup " + hotspotTable()) == std::string::npos) return false;
            for (const auto& name : hotspotInterfaces)
                if (command(hotspotHook(family, "-C", name)) != 0 || command(hotspotInput(family, "-C", name)) != 0) return false;
        }
        return true;
    }
    void clearHotspot() {
        for (int family : {4, 6}) {
            // Reconstruct only our exact hooks, including when the interface
            // disappeared or this process is recovering an old journal.
            std::string listing; command(mangle(family, {"-S", "PREROUTING"}), &listing);
            std::istringstream lines(listing); std::string line;
            while (std::getline(lines, line)) {
                std::istringstream tokens(line); std::string a, b, c, name, d, target, extra;
                if (tokens >> a >> b >> c >> name >> d >> target && !(tokens >> extra) &&
                    a == "-A" && b == "PREROUTING" && c == "-i" && d == "-j" && target == hotspotChain() && validHotspotInterface(name)) {
                    command(hotspotHook(family, "-D", name)); command(hotspotInput(family, "-D", name));
                }
            }
            // Handle a crash between INPUT installation and PREROUTING.
            command(filter(family, {"-S", "INPUT"}), &listing);
            std::istringstream inputs(listing);
            while (std::getline(inputs, line)) {
                std::istringstream tokens(line); std::string a, b, c, name;
                if (tokens >> a >> b >> c >> name && a == "-A" && b == "INPUT" && c == "-i" && validHotspotInterface(name))
                    if (command(hotspotInput(family, "-C", name)) == 0) command(hotspotInput(family, "-D", name));
            }
            for (const auto& suffix : {"", "_S", "_D", "_F"}) command(mangle(family, {"-F", hotspotChain() + suffix}));
            for (const auto& suffix : {"", "_S", "_D", "_F"}) command(mangle(family, {"-X", hotspotChain() + suffix}));
            command(hotspotRouteRule(family, "del"));
            command(ip(family, {"route", "del", "local", "default", "dev", "lo", "table", hotspotTable()}));
            for (const auto& suffix : {"", "_S", "_D", "_F"})
                require(command(mangle(family, {"-S", hotspotChain() + suffix})) != 0, "BF-ROOT-CLEANUP");
            std::string rules;
            require(command(ip(family, {"rule", "show"}), &rules) == 0 &&
                rules.find("lookup " + hotspotTable()) == std::string::npos, "BF-ROOT-CLEANUP");
        }
        hotspotInterfaces.clear();
        unlink((journal + ".hotspot").c_str());
    }
    bool ready() const {
        if (policy.local_origin && !hotspotReady()) return false;
        if (policy.dns4_tproxy) {
            std::string routes, rules;
            if (command(ip(4, {"route", "show", "table", dnsTable()}), &routes) != 0 ||
                routes.find("local default dev lo") == std::string::npos ||
                command(ip(4, {"rule", "show"}), &rules) != 0 ||
                rules.find("99:") == std::string::npos || rules.find("lookup " + dnsTable()) == std::string::npos) return false;
        }
        for (int family : {4, 6}) for (const auto& args : physicalDnsFilters(family, "-C"))
            if (command(args) != 0) return false;
        if (if_nametoindex(iface.c_str()) == 0) return false;
        for (int family : {4, 6}) for (const auto& args : coexistDnsFilters(family, "-C"))
            if (command(args) != 0) return false;
        if (policy.local_dns) for (const auto& range : localDnsRanges()) for (const auto& protocol : {"udp", "tcp"})
            if (command(dnsRule("-C", range, protocol)) != 0) return false;
        if (policy.local_dns) {
            for (const auto& args : dnsProxyRules("-C")) if (command(args) != 0) return false;
            std::string routes, rules;
            if (command(ip(6, {"route", "show", "table", dnsTable()}), &routes) != 0 ||
                routes.find("local default dev lo") == std::string::npos ||
                command(ip(6, {"rule", "show"}), &rules) != 0 || rules.find("lookup " + dnsTable()) == std::string::npos) return false;
            for (const auto& entry : dnsInterfaces)
                if (routes.find("local fe80::/10 dev " + entry.first + " ") == std::string::npos) return false;
        }
        for (int family : {4, 6}) {
            std::string routes, rules;
            if (command(ip(family, {"route", "show", "table", table}), &routes) != 0 ||
                routes.find("default dev " + iface) == std::string::npos ||
                command(ip(family, {"rule", "show"}), &rules) != 0) return false;
            for (auto range : policy.ranges) {
                if (rules.find("uidrange " + range + " lookup " + table) == std::string::npos) return false;
                std::replace(range.begin(), range.end(), '-', ':');
                if (command(filter(family, {"-C", "OUTPUT", "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", "0x20000/0x20000", "-j", chain})) != 0)
                    return false;
            }
            if (policy.owner_fake_ip && !ownerFakeReady(family, rules)) return false;
            if (policy.coexist_dns) for (auto uid : policy.bypass_uids)
                if (rules.find("fwmark 0x4000000/0x5000000 uidrange " + number(uid) + "-" + number(uid) + " lookup " + table) == std::string::npos) return false;
            for (const auto& prefix : coexistPrefixes(family))
                if (routes.find("throw " + prefix) == std::string::npos) return false;
        }
        return true;
    }
    bool cleanup() {
        if (policy.local_origin) clearHotspot();
        for (int family : {4, 6}) {
            for (const auto& args : coexistDnsFilters(family, "-D")) command(args);
            for (const auto& args : physicalDnsFilters(family, "-D")) command(args);
            if (policy.coexist_dns) for (auto uid : policy.bypass_uids) command(coexistDnsRoute(family, "del", uid));
        }
        if (policy.local_dns) for (const auto& range : localDnsRanges()) for (const auto& protocol : {"udp", "tcp"})
            command(dnsRule("-D", range, protocol));
        if (policy.local_dns) {
            for (const auto& args : dnsProxyRules("-D")) command(args);
            command(dnsRouteRule("del"));
            clearDnsInterfaceRoutes();
            clearDns4Routes();
            command(ip(6, {"route", "del", "local", "default", "dev", "lo", "table", dnsTable()}));
        }
        for (int family : {4, 6}) {
            // Delete exact selectors from the app-private journal; never flush
            // the system table or another application's routing/filter rules.
            for (const auto& range : policy.ranges) command(rule(family, "del", range));
            if (policy.owner_fake_ip) {
                command(ownerFakeRule(family, "del"));
                command(ownerFakeFence(family, "-D"));
            }
            for (auto range : policy.ranges) {
                std::replace(range.begin(), range.end(), '-', ':');
                command(filter(family, {"-D", "OUTPUT", "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", "0x20000/0x20000", "-j", chain}));
            }
            command(filter(family, {"-F", chain}));
            command(filter(family, {"-X", chain}));
            for (const auto& prefix : coexistPrefixes(family)) command(coexistRoute(family, "del", prefix));
            command(ip(family, {"route", "del", "default", "dev", iface, "table", table}));
        }
        if (present()) return false;
        if (tun >= 0) { close(tun); tun = -1; }
        unlink(journal.c_str()); created = false; return true;
    }
    void fence(bool enabled) {
        if (policy.local_origin) hotspotFence(enabled);
        for (int family : {4, 6}) {
            if (enabled) {
                for (const auto& prefix : coexistPrefixes(family))
                    if (command(filter(family, {"-C", chain, "-d", prefix, "-j", "RETURN"})) != 0)
                        run(filter(family, {"-I", chain, "1", "-d", prefix, "-j", "RETURN"}));
                // Only root-owned local IPC bypasses the external-traffic
                // fence. Health/quality SOCKS clients and their accepted TCP
                // replies must work before READY; no external route is opened.
                if (policy.protected_mark && command(filter(family, {"-C", chain, "-m", "owner", "--uid-owner", "0", "-o", "lo", "-j", "RETURN"})) != 0)
                    run(filter(family, {"-I", chain, "1", "-m", "owner", "--uid-owner", "0", "-o", "lo", "-j", "RETURN"}));
                // A single DROP is atomic and is scoped by OUTPUT's UID
                // matches. Do not flush a live blocking rule before replacing.
                if (command(filter(family, {"-C", chain, "-j", "DROP"})) != 0)
                    run(filter(family, {"-A", chain, "-j", "DROP"}));
            } else run(filter(family, {"-F", chain}));
        }
    }
    void create() {
        if (policy.dns4_tproxy) {
            std::string existing;
            require(command(ip(4, {"route", "show", "table", dnsTable()}), &existing) == 0 && existing.empty(), "BF-ROOT-COLLISION");
        }
        require(if_nametoindex(iface.c_str()) == 0 && !present(), "BF-ROOT-COLLISION");
        if (policy.local_dns) {
            std::string existing;
            require(command(ip(6, {"route", "show", "table", dnsTable()}), &existing) == 0 && existing.empty(), "BF-ROOT-COLLISION");
        }
        for (int family : {4, 6}) {
            std::string existing;
            require(command(ip(family, {"route", "show", "table", table}), &existing) == 0 && existing.empty(),
                "BF-ROOT-COLLISION");
            require(command(filter(family, {"-S", chain})) != 0, "BF-ROOT-COLLISION");
        }
        int record = open(journal.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        require(record >= 0, "BF-ROOT-JOURNAL");
        std::string text = policy.wire + "\n";
        bool saved = write(record, text.data(), text.size()) == ssize_t(text.size()) && fsync(record) == 0;
        close(record); require(saved, "BF-ROOT-JOURNAL"); created = true;
        tun = open("/dev/tun", O_RDWR | O_CLOEXEC);
        if (tun < 0) tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        require(tun >= 0, "BF-ROOT-TUN");
        ifreq request{}; request.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(request.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        require(ioctl(tun, TUNSETIFF, &request) == 0, "BF-ROOT-TUN");
        run({"/system/bin/ip", "link", "set", "dev", iface, "mtu", "1500", "up"});
        run(ip(4, {"address", "add", "172.19.0.1/30", "dev", iface}));
        run(ip(6, {"address", "add", "fdfe:dcba:9876::1/126", "dev", iface, "nodad"}));
        for (int family : {4, 6}) {
            run(filter(family, {"-N", chain}));
            if (policy.protected_mark)
                run(filter(family, {"-A", chain, "-m", "owner", "--uid-owner", "0", "-o", "lo", "-j", "RETURN"}));
            run(filter(family, {"-A", chain, "-j", "DROP"}));
            for (const auto& prefix : coexistPrefixes(family)) {
                run(filter(family, {"-I", chain, "1", "-d", prefix, "-j", "RETURN"}));
                run(coexistRoute(family, "add", prefix));
            }
            for (auto range : policy.ranges) {
                std::replace(range.begin(), range.end(), '-', ':');
                run(filter(family, {"-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", range, "-m", "mark", "!", "--mark", "0x20000/0x20000", "-j", chain}));
            }
            run(ip(family, {"route", "add", "default", "dev", iface, "table", table}));
            for (const auto& range : policy.ranges) run(rule(family, "add", range));
            if (policy.owner_fake_ip) {
                run(ownerFakeFence(family, "-A"));
                run(ownerFakeRule(family, "add"));
            }
            if (policy.coexist_dns) for (auto uid : policy.bypass_uids) run(coexistDnsRoute(family, "add", uid));
            for (const auto& args : coexistDnsFilters(family, "-I")) run(args);
            for (const auto& args : physicalDnsFilters(family, "-I")) run(args);
        }
        if (policy.local_dns) {
            if (policy.dns4_tproxy) {
                run(ip(4, {"route", "add", "local", "default", "dev", "lo", "table", dnsTable()}));
                run(dns4RouteRule("add"));
            }
            run(ip(6, {"route", "add", "local", "default", "dev", "lo", "table", dnsTable()}));
            refreshDnsRoutes();
            run(dnsRouteRule("add"));
            for (const auto& args : dnsProxyRules("-I")) run(args);
            for (const auto& range : localDnsRanges()) for (const auto& protocol : {"udp", "tcp"}) run(dnsRule("-I", range, protocol));
        }
    }
    void send_tun(int socket) const {
        char payload = 'T'; iovec vector{&payload, 1};
        char control[CMSG_SPACE(sizeof(int))]{}; msghdr message{};
        message.msg_iov = &vector; message.msg_iovlen = 1;
        message.msg_control = control; message.msg_controllen = sizeof(control);
        auto cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &tun, sizeof(int));
        require(sendmsg(socket, &message, MSG_NOSIGNAL) == 1, "BF-ROOT-FD");
    }
};
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, signal_stop); signal(SIGINT, signal_stop);
    int socket_fd = -1, lock_fd = -1, exit_status = 0;
    Boundary* boundary = nullptr;
    try {
        require(geteuid() == 0, "BF-ROOT-PERMISSION");
        if (argc == 2 && std::string(argv[1]) == "--probe") {
            require(access("/system/bin/ip", X_OK) == 0 && access("/system/bin/ip6tables", X_OK) == 0, "BF-ROOT-UNSUPPORTED");
            puts("BFR1 ROOT TCP UDP IPV6"); return 0;
        }
        require(argc == 4 || (argc == 5 && std::string(argv[4]) == "--daemon"), "BF-ROOT-ARGS");
        const bool daemon = argc == 5;
        std::string name(argv[1]), state(argv[3]);
        require(name.size() == 77 && name.rfind("bifrost-root-", 0) == 0 &&
            name.substr(13).find_first_not_of("0123456789abcdef") == std::string::npos, "BF-ROOT-ARGS");
        char* tail; unsigned owner = strtoul(argv[2], &tail, 10);
        require(*tail == 0 && owner % 100000 >= 10000 && owner < 2000000000, "BF-ROOT-ARGS");
        char resolved[4096]; require(realpath(state.c_str(), resolved) && state == resolved, "BF-ROOT-PATH");
        struct stat info{}; require(lstat(state.c_str(), &info) == 0 && S_ISDIR(info.st_mode) &&
            info.st_uid == owner && (info.st_mode & 0022) == 0, "BF-ROOT-PATH");
        lock_fd = open((state + "/lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        require(lock_fd >= 0 && flock(lock_fd, LOCK_EX | LOCK_NB) == 0, "BF-ROOT-ACTIVE");
        socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); require(socket_fd >= 0, "BF-ROOT-SOCKET");
        sockaddr_un address{}; address.sun_family = AF_UNIX; memcpy(address.sun_path + 1, name.data(), name.size());
        require(connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
            offsetof(sockaddr_un, sun_path) + 1 + name.size()) == 0, "BF-ROOT-SOCKET");
        ucred peer{}; socklen_t size = sizeof(peer);
        require(getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && unsigned(peer.uid) == (daemon ? 0 : owner),
            "BF-ROOT-PEER");
        auto policy = Policy::parse(read_line(socket_fd), owner);
        std::string journal = state + "/journal";
        if (lstat(journal.c_str(), &info) == 0) {
            require(S_ISREG(info.st_mode) && info.st_uid == 0 && (info.st_mode & 0077) == 0 && info.st_size < 8192,
                "BF-ROOT-JOURNAL");
            std::ifstream previous(journal); std::string line; std::getline(previous, line);
            Boundary recovery(Policy::parse(line, owner), journal);
            require(recovery.cleanup(), "BF-ROOT-CLEANUP");
        }
        boundary = new Boundary(policy, journal); boundary->create();
        if (policy.local_origin) boundary->createHotspot();
        boundary->send_tun(socket_fd);
        while (!quitting) {
            auto op = read_line(socket_fd, 24 * 3600);
            if (op.rfind("OWNER ", 0) == 0) {
                try { reply(socket_fd, connection_owner(op)); }
                catch (...) { reply(socket_fd, "BF-OWNER-NOT-FOUND"); }
                continue;
            }
            if (op.rfind("HOTSPOT ", 0) == 0) boundary->setHotspotMode(op.substr(8));
            else if (op == "TETHER") boundary->refreshHotspot();
            else if (op.rfind("DNS ", 0) == 0) boundary->updateDns(op);
            else if (op == "BLOCK") boundary->fence(true);
            else if (op == "READY") { boundary->refreshDnsRoutes(); boundary->fence(false); }
            else if (op == "NETWORK") { boundary->refreshDnsRoutes(); boundary->refreshHotspot(true); }
            else if (op == "STATUS") { boundary->refreshDnsRoutes(); boundary->refreshHotspot(true); require(boundary->ready(), "BF-ROOT-READBACK"); }
            else if (op == "STOP") {
                require(boundary->cleanup(), "BF-ROOT-CLEANUP"); reply(socket_fd, "OK"); break;
            } else throw std::runtime_error("BF-ROOT-PROTOCOL");
            reply(socket_fd, "OK");
        }
    } catch (const std::exception& error) {
        exit_status = 1;
        if (socket_fd >= 0) { try { reply(socket_fd, error.what()); } catch (...) {} }
        fprintf(stderr, "%s\n", error.what());
    }
    if (boundary && boundary->created) {
        try { boundary->cleanup(); } catch (...) { fprintf(stderr, "BF-ROOT-CLEANUP\n"); }
    }
    delete boundary;
    if (socket_fd >= 0) close(socket_fd);
    if (lock_fd >= 0) close(lock_fd);
    return exit_status;
}
