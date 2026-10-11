// Run only as root inside a fresh `unshare -n` namespace. This exercises real
// Linux policy routing using the exact native helper command builders.
#define main bifrost_boundary_entry
#include "../../main/cpp/bifrost_root.cpp"
#undef main
#include <cassert>

static void execute(Args args) {
    args[0] = "/usr/sbin/ip";
    run(args);
}
int main() {
    struct stat current{}, initial{};
    require(geteuid() == 0 && stat("/proc/self/ns/net", &current) == 0 &&
        stat("/proc/1/ns/net", &initial) == 0 && current.st_ino != initial.st_ino, "TEST-REQUIRES-ISOLATED-NETNS");
    std::string links;
    require(command({"/usr/sbin/ip", "-o", "link", "show"}, &links) == 0 &&
        std::count(links.begin(), links.end(), '\n') == 1 && links.find("lo:") != std::string::npos, "TEST-REQUIRES-FRESH-NETNS");
    auto ip = [](Args args) { args.insert(args.begin(), "/usr/sbin/ip"); run(args); };
    for (const auto* name : {"phy0", "tail0", "bfr10403"}) {
        ip({"link", "add", name, "type", "dummy"});
        ip({"link", "set", name, "up"});
    }
    ip({"address", "add", "192.0.2.2/24", "dev", "phy0"});
    ip({"address", "add", "100.64.0.1/32", "dev", "tail0"});
    ip({"address", "add", "172.19.0.1/30", "dev", "bfr10403"});
    ip({"-6", "address", "add", "2001:db8::2/64", "dev", "phy0", "nodad"});
    ip({"-6", "address", "add", "fd7a:115c:a1e0::1/128", "dev", "tail0", "nodad"});
    ip({"-6", "address", "add", "fdfe:dcba:9876::1/126", "dev", "bfr10403", "nodad"});
    Boundary boundary(Policy::parse("BFR8 10403 none 0 1 10500 2 192.168.20.1 fd00::53", 10403), "/unused");
    for (int family : {4, 6}) {
        execute(boundary.ip(family, {"route", "add", "default", "dev", "phy0"}));
        execute(boundary.ip(family, {"route", "add", "default", "dev", boundary.iface, "table", boundary.table}));
        for (const auto& prefix : boundary.coexistPrefixes(family)) {
            execute(boundary.ip(family, {"route", "add", prefix, "dev", "tail0", "table", "50110"}));
            execute(boundary.coexistRoute(family, "add", prefix));
        }
        for (const auto& range : boundary.policy.ranges) execute(boundary.rule(family, "add", range));
        execute(boundary.ownerFakeRule(family, "add"));
        execute(boundary.coexistDnsRoute(family, "add", 10500));
        execute(boundary.ip(family, {"rule", "add", "priority", "12000", "fwmark", "0/0x20000", "lookup", "50110"}));
    }
    auto check = [&](int family, const std::string& destination, unsigned uid, const std::string& expected, const std::string& mark = "0") {
        auto args = boundary.ip(family, {"route", "get", destination, "mark", mark, "uid", number(uid)});
        args[0] = "/usr/sbin/ip";
        std::string result;
        require(command(args, &result) == 0 && result.find("dev " + expected + " ") != std::string::npos, "TEST-ROUTING-MISMATCH");
    };
    check(4, "1.1.1.1", 10600, "bfr10403");
    check(4, "100.100.100.100", 10600, "tail0");
    check(4, "10.20.30.40", 10600, "tail0");
    check(4, "192.168.20.40", 10600, "tail0");
    check(4, "1.1.1.1", 10500, "phy0");
    check(4, "1.1.1.1", 10500, "phy0", "0x20000");
    check(4, "1.1.1.1", 10500, "bfr10403", "0x4020000");
    check(4, "1.1.1.1", 10500, "phy0", "0x5020000");
    check(4, "100.100.100.100", 10500, "tail0", "0x4000000");
    check(4, "10.20.30.40", 10500, "tail0", "0x4000000");
    check(4, "1.1.1.1", 0, "phy0", "0x1020000");
    check(4, "1.1.1.1", 0, "bfr10403", "0x20000");
    check(4, "198.18.0.8", 10403, "bfr10403");
    check(6, "fc00::8", 10403, "bfr10403");
    check(6, "2001:4860:4860::8888", 10600, "bfr10403");
    check(6, "fd7a:115c:a1e0::8", 10600, "tail0");
    check(6, "2001:4860:4860::8888", 10500, "phy0");
    check(6, "2001:4860:4860::8888", 10500, "bfr10403", "0x4020000");
    check(6, "fd7a:115c:a1e0::53", 10500, "tail0", "0x4000000");
    // Another VPN can withdraw/reinstall its own routes after Root starts.
    // Root neither rewrites its table nor requires a tunnel restart.
    for (int repeat = 0; repeat < 3; ++repeat) {
        execute(boundary.ip(4, {"route", "del", "100.64.0.0/10", "dev", "tail0", "table", "50110"}));
        check(4, "1.1.1.1", 10600, "bfr10403");
        execute(boundary.ip(4, {"route", "add", "100.64.0.0/10", "dev", "tail0", "table", "50110"}));
        check(4, "100.100.100.100", 10600, "tail0");
    }
    // Exact cleanup keeps the simulated other VPN and physical routes alive.
    for (int family : {4, 6}) {
        for (const auto& range : boundary.policy.ranges) execute(boundary.rule(family, "del", range));
        execute(boundary.ownerFakeRule(family, "del"));
        execute(boundary.coexistDnsRoute(family, "del", 10500));
        for (const auto& prefix : boundary.coexistPrefixes(family)) execute(boundary.coexistRoute(family, "del", prefix));
        execute(boundary.ip(family, {"route", "del", "default", "dev", boundary.iface, "table", boundary.table}));
        auto args = boundary.ip(family, {"route", "show", "table", boundary.table}); args[0] = "/usr/sbin/ip";
        std::string routes; require(command(args, &routes) == 0 && routes.empty(), "TEST-RESIDUAL-ROUTE");
    }
    check(4, "1.1.1.1", 10600, "phy0");
    check(4, "100.100.100.100", 10600, "tail0");
    puts("ROOT-ROUTING PASS: dual stack, MagicDNS, subnet routes, transport bypass, own fake DNS, scoped cleanup (isolated Linux netns)");
}
