#pragma once

// AOSP Fwmark uses bits 0..20 for netId/permissions/billing, 29..30 for
// vendors, and 31 for wakeup. Keep Android's protectedFromVpn bit for its
// own routing, but distinguish our upstream sockets from netd's DNS sockets.
// Both native users include this header so the dialer and TUN rules agree.
constexpr unsigned BIFROST_ROOT_SOCKET_MARK = 0x01000000;
constexpr unsigned ANDROID_PROTECTED_FROM_VPN = 0x00020000;
constexpr const char* BIFROST_ROOT_MARK_MATCH = "0x1000000/0x1000000";
constexpr const char* BIFROST_ROOT_UNMARKED_MATCH = "0/0x1000000";
