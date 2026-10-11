#include "../../main/cpp/bifrost_connection_owner.h"
#include <cassert>
#include <chrono>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    const auto started = std::chrono::steady_clock::now();
    for (int family : {AF_INET, AF_INET6}) {
        int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        sockaddr_storage peer{}, local{};
        socklen_t size;
        std::string host;
        if (family == AF_INET) {
            auto* address = reinterpret_cast<sockaddr_in*>(&peer);
            address->sin_family = AF_INET; address->sin_port = htons(54321);
            inet_pton(AF_INET, "127.0.0.1", &address->sin_addr);
            size = sizeof(sockaddr_in); host = "127.0.0.1";
        } else {
            auto* address = reinterpret_cast<sockaddr_in6*>(&peer);
            address->sin6_family = AF_INET6; address->sin6_port = htons(54321);
            inet_pton(AF_INET6, "::1", &address->sin6_addr);
            size = sizeof(sockaddr_in6); host = "::1";
        }
        assert(connect(fd, reinterpret_cast<sockaddr*>(&peer), size) == 0);
        assert(getsockname(fd, reinterpret_cast<sockaddr*>(&local), &size) == 0);
        auto port = ntohs(family == AF_INET ? reinterpret_cast<sockaddr_in*>(&local)->sin_port : reinterpret_cast<sockaddr_in6*>(&local)->sin6_port);
        const auto query = "OWNER 17 " + host + " " + std::to_string(port) + " " + host + " 54321";
        for (int i = 0; i < 50; ++i)
            assert(bifrost_owner::connection_owner(query) == "UID " + std::to_string(getuid()));
        close(fd);
        bool rejected = false;
        try { bifrost_owner::connection_owner(query); } catch (...) { rejected = true; }
        assert(rejected);
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    printf("Root owner PASS: 100 IPv4/IPv6 lookups, closed socket rejected, total=%lld ms\n", static_cast<long long>(elapsed));
}
