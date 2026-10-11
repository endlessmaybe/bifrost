// Standalone Android/NDK fixture. Compiling the real boundary implementation
// keeps journal compatibility and owner-only selectors under the same parser.
#define main bifrost_boundary_entry
#include "../../main/cpp/bifrost_root.cpp"
#undef main
#include <cassert>

int main() {
    {
        auto current = Policy::parse("BFR13 10403 none 0 1 10500 1 192.168.31.1 smart", 10403);
        assert(current.local_origin && current.dns4_tproxy && current.hotspot_mode == "smart");
        Boundary boundary(current, "/unused");
        for (int family : {4, 6}) {
            auto rule = boundary.rule(family, "add", "0-10402");
            auto ingress = std::find(rule.begin(), rule.end(), "iif");
            assert(ingress != rule.end() && *(ingress + 1) == "lo");
            Boundary legacy(Policy::parse("BFR12 10403 none 0 1 10500 0", 10403), "/unused");
            auto old = legacy.rule(family, "del", "0-10402");
            assert(std::find(old.begin(), old.end(), "iif") == old.end());
            auto hook = boundary.hotspotHook(family, "-I", "wlan2");
            assert(std::find(hook.begin(), hook.end(), "wlan2") != hook.end());
        }
        auto next = boundary.updatedDnsPolicy("DNS 223.5.5.5");
        assert(next.local_origin && next.hotspot_mode == "smart" && next.wire.find("BFR13 ") == 0);
        auto direct = Policy::parse("BFR13 10403 none 0 0 0 direct", 10403);
        assert(direct.hotspot_mode == "direct");
        assert((Boundary::parseTetherInterfaces("21000: from all iif wlan2 lookup wlan0\n9000: from all iif lo lookup 40403\n") == std::vector<std::string>{"wlan2"}));
        assert(Boundary::parseTetherInterfaces("21000: from all iif lo lookup wlan0\n21000: from all iif bad/name lookup wlan0\n").empty());
        bool rejected = false;
        try { Policy::parse("BFR13 10403 none 0 0 0 invalid", 10403); } catch (...) { rejected = true; }
        assert(rejected);
        puts("BFR13 PASS: local-only UID capture, tether discovery, direct/smart, old-journal cleanup");
    }
    for (const auto* version : {"BFR1", "BFR2", "BFR3", "BFR4"}) {
        auto old = Policy::parse(std::string(version) + " 10403 none 0", 10403);
        assert(!old.owner_fake_ip);
        assert((old.ranges == std::vector<std::string>{"0-10402", "10404-99999"}));
    }
    for (const auto* mode : {"none 0", "allow 1 10500", "exclude 1 10500"}) {
        auto policy = Policy::parse(std::string("BFR5 10403 ") + mode, 10403);
        assert(policy.owner_fake_ip && policy.dedicated_mark && policy.local_dns);
        Boundary boundary(policy, "/data/local/tmp/bifrost-policy-fixture-unused");
        for (const int family : {4, 6}) {
            auto add = boundary.ownerFakeRule(family, "add");
            auto remove = boundary.ownerFakeRule(family, "del");
            std::replace(add.begin(), add.end(), std::string("add"), std::string("del"));
            assert(add == remove);
            assert(std::find(add.begin(), add.end(), "10403-10403") != add.end());
            assert(std::find(add.begin(), add.end(), family == 4 ? "198.18.0.0/15" : "fc00::/18") != add.end());
            assert(std::find(add.begin(), add.end(), BIFROST_ROOT_UNMARKED_MATCH) != add.end());
            auto fence = boundary.ownerFakeFence(family, "-A");
            assert(std::find(fence.begin(), fence.end(), "10403") != fence.end());
            assert(std::find(fence.begin(), fence.end(), "-d") != fence.end());
            assert(std::find(fence.begin(), fence.end(), BIFROST_ROOT_MARK_MATCH) != fence.end());
        }
    }
    for (const auto* mode : {"none 0", "allow 2 10500 10600", "exclude 1 10600"}) {
        auto policy = Policy::parse(std::string("BFR6 10403 ") + mode + " 2 10500 10500", 10403);
        assert(policy.bypass_uids == std::vector<unsigned>{10500});
        auto captured = [&](unsigned uid) {
            for (const auto& range : policy.ranges) {
                auto split = range.find('-');
                if (uid >= std::stoul(range.substr(0, split)) && uid <= std::stoul(range.substr(split + 1))) return true;
            }
            return false;
        };
        assert(!captured(10403) && !captured(10500));
        assert(captured(10600) == (policy.mode != "exclude"));
        assert(captured(10700) == (policy.mode != "allow"));
        Boundary boundary(policy, "/unused");
        for (int family : {4, 6}) for (const auto& prefix : boundary.coexistPrefixes(family)) {
            auto add = boundary.coexistRoute(family, "add", prefix);
            std::replace(add.begin(), add.end(), std::string("add"), std::string("del"));
            assert(add == boundary.coexistRoute(family, "del", prefix));
            assert(std::find(add.begin(), add.end(), "throw") != add.end());
            assert(std::find(add.begin(), add.end(), "40403") != add.end());
            assert(prefix != "0.0.0.0/0" && prefix != "::/0" && prefix != "fc00::/18");
        }
    }
    for (const auto* version : {"BFR1", "BFR2", "BFR3", "BFR4", "BFR5"}) {
        Boundary legacy(Policy::parse(std::string(version) + " 10403 none 0", 10403), "/unused");
        assert(legacy.coexistPrefixes(4).empty() && legacy.coexistPrefixes(6).empty());
    }
    Boundary solo(Policy::parse("BFR6 10403 none 0 0", 10403), "/unused");
    assert(solo.coexistPrefixes(4).empty() && solo.coexistPrefixes(6).empty());
    for (const auto* wire : {"BFR6 10403 none 0", "BFR6 10403 none 0 17", "BFR6 10403 none 0 1 0",
            "BFR6 10403 none 0 1 10403", "BFR6 10403 none 0 1 110500", "BFR5 10403 none 0 1 10500"}) {
        bool rejected = false;
        try { Policy::parse(wire, 10403); } catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
    Boundary current(Policy::parse("BFR7 10403 none 0 1 10500", 10403), "/unused");
    Boundary previous(Policy::parse("BFR6 10403 none 0 1 10500", 10403), "/unused");
    for (int family : {4, 6}) {
        assert(previous.coexistDnsFilters(family, "-D").empty());
        const auto filters = current.coexistDnsFilters(family, "-I");
        assert(filters.size() == 3);
        auto deletes = current.coexistDnsFilters(family, "-D");
        for (size_t i = 0; i < filters.size(); ++i) {
            auto add = filters[i];
            std::replace(add.begin(), add.end(), std::string("-I"), std::string("-D"));
            assert(add == deletes[i]);
            assert(std::find(add.begin(), add.end(), "10500") != add.end());
            if (i > 0) assert(std::find(add.begin(), add.end(), "53") != add.end());
        }
        auto add = current.coexistDnsRoute(family, "add", 10500);
        std::replace(add.begin(), add.end(), std::string("add"), std::string("del"));
        assert(add == current.coexistDnsRoute(family, "del", 10500));
    }
    Boundary wifi(Policy::parse("BFR8 10403 none 0 1 10500 2 192.168.20.1 fd00::53", 10403), "/unused");
    for (int family : {4, 6}) {
        assert(current.physicalDnsFilters(family, "-D").empty());
        auto filters = wifi.physicalDnsFilters(family, "-I");
        auto deletes = wifi.physicalDnsFilters(family, "-D");
        assert(filters.size() == 2);
        for (size_t i = 0; i < filters.size(); ++i) {
            auto add = filters[i];
            std::replace(add.begin(), add.end(), std::string("-I"), std::string("-D"));
            assert(add == deletes[i]);
            for (auto value : {"10500", "53", "DNAT", "-d", "nat"}) assert(std::find(add.begin(), add.end(), value) != add.end());
        }
    }
    for (auto address : {"bad.example", "1.2.3.4/0", "127.0.0.1", "::1", "::", "fe80::1", "224.0.0.1"}) {
        bool rejected = false;
        try { Policy::parse(std::string("BFR8 10403 none 0 1 10500 1 ") + address, 10403); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
    Boundary https(Policy::parse("BFR9 10403 none 0 1 10500 0", 10403), "/unused");
    for (int family : {4, 6}) {
        auto rules = https.coexistDnsFilters(family, "-I");
        assert(rules.size() == 4);
        assert(std::find(rules.back().begin(), rules.back().end(), "tcp") != rules.back().end());
        assert(std::find(rules.back().begin(), rules.back().end(), "443") != rules.back().end());
        auto add = rules.back();
        std::replace(add.begin(), add.end(), std::string("-I"), std::string("-D"));
        assert(add == https.coexistDnsFilters(family, "-D").back());
    }
    Boundary cellular(Policy::parse("BFR10 10403 none 0 1 10500 2 1.1.1.1 2409:8034:2000::3", 10403), "/unused");
    assert(cellular.policy.physical_dns_tproxy);
    auto v6 = cellular.physicalDnsFilters(6, "-I");
    assert(v6.size() == 2);
    for (auto args : v6) {
        assert(std::find(args.begin(), args.end(), "nat") == args.end());
        assert(std::find(args.begin(), args.end(), "mangle") != args.end());
        assert(std::find(args.begin(), args.end(), "2409:8034:2000::3") != args.end());
        assert(std::find(args.begin(), args.end(), "0x2000000/0x2000000") != args.end());
    }
    assert(cellular.dnsLocalPrefixes().size() == 2);
    assert(cellular.dnsLocalPrefixes()[1] == "2409:8034:2000::3/128");
    auto coexist = cellular.coexistDnsMark(6, "-I", 10500, "udp");
    assert(std::find(coexist.begin(), coexist.end(), "0x2000000/0x2000000") != coexist.end());
    Boundary split(Policy::parse("BFR11 10403 none 0 1 10500 2 192.168.31.1 2409:8034:2000::3", 10403), "/unused");
    assert(split.policy.split_dns);
    auto dns4 = split.physicalDnsFilters(4, "-I");
    assert(dns4.size() == (split.policy.ranges.size() + 1) * 2);
    auto remove4 = split.physicalDnsFilters(4, "-D");
    for (size_t i = 0; i < dns4.size(); ++i) {
        auto args = dns4[i];
        assert(std::find(args.begin(), args.end(), "-d") == args.end());
        const bool app = i < split.policy.ranges.size() * 2;
        assert(std::find(args.begin(), args.end(), app ? "127.0.0.1:15355" : "127.0.0.1:15354") != args.end());
        std::replace(args.begin(), args.end(), std::string("-I"), std::string("-D"));
        assert(args == remove4[i]);
    }
    assert(split.physicalDnsFilters(6, "-I").empty());
    auto appRule = split.dnsRule("-I", "10404-10499", "udp");
    auto vpnRule = split.dnsRule("-I", "10500-10500", "udp");
    assert(std::find(appRule.begin(), appRule.end(), "0x2000000/0x2000000") != appRule.end());
    assert(std::find(vpnRule.begin(), vpnRule.end(), "0xa000000/0xa000000") != vpnRule.end());
    assert(std::find(appRule.begin(), appRule.end(), "fe80::/10") == appRule.end());
    assert(split.dnsProxyRules("-I").size() == 4);
    auto tailProxy = split.dnsProxyRule("-I", "tcp", true);
    assert(std::find(tailProxy.begin(), tailProxy.end(), "15356") != tailProxy.end());
    Boundary noVpn(Policy::parse("BFR11 10403 none 0 0 1 192.168.31.1", 10403), "/unused");
    assert(noVpn.dnsProxyRules("-I").size() == 2);
    puts("BFR11 split DNS PASS: app/VPN UID isolation, IPv6 no NAT, exact removal");
    Boundary transparent(Policy::parse("BFR12 10403 none 0 1 10500 1 192.168.31.1", 10403), "/unused");
    assert(transparent.policy.dns4_tproxy);
    auto marks4 = transparent.physicalDnsFilters(4, "-I");
    auto delMarks4 = transparent.physicalDnsFilters(4, "-D");
    assert(marks4.size() == (transparent.policy.ranges.size() + 1) * 2);
    for (size_t i = 0; i < marks4.size(); ++i) {
        auto args = marks4[i];
        assert(std::find(args.begin(), args.end(), "DNAT") == args.end());
        assert(std::find(args.begin(), args.end(), "MARK") != args.end());
        std::replace(args.begin(), args.end(), std::string("-I"), std::string("-D"));
        assert(args == delMarks4[i]);
    }
    assert(transparent.dnsProxyRules("-I").size() == 8);
    auto app4 = transparent.dnsProxyRule("-I", "udp", false, 4);
    auto infra4 = transparent.dnsProxyRule("-I", "udp", true, 4);
    assert(app4.front() == "/system/bin/iptables");
    assert(std::find(app4.begin(), app4.end(), "15355") != app4.end());
    assert(std::find(infra4.begin(), infra4.end(), "15354") != infra4.end());
    auto dns4Rule = transparent.dns4RouteRule("add");
    assert(std::find(dns4Rule.begin(), dns4Rule.end(), "99") != dns4Rule.end());
    std::replace(dns4Rule.begin(), dns4Rule.end(), std::string("add"), std::string("del"));
    assert(dns4Rule == transparent.dns4RouteRule("del"));
    auto wifiDns = transparent.updatedDnsPolicy("DNS 192.168.31.1 240e::1");
    assert(wifiDns.dns_servers.size() == 2);
    transparent.policy = wifiDns;
    auto mobileDns = transparent.updatedDnsPolicy("DNS 211.143.147.120 2409::4");
    assert(mobileDns.dns_servers.size() == 2);
    assert(!mobileDns.dns_servers.count("192.168.31.1"));
    assert(!mobileDns.dns_servers.count("240e::1"));
    assert(mobileDns.dns_servers.count("211.143.147.120"));
    assert(mobileDns.dns_servers.count("2409::4"));
    puts("BFR12 PASS: IPv4 transparent DNS, UID isolation, exact removal, legacy preservation");
    puts("ROOT-POLICY PASS: BFR1-9 journals, DNS-only mark and DNAT, exact cleanup, app policy");
}
