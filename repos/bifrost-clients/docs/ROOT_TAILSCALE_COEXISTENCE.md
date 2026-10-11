# Root 与 Tailscale 共存修复

范围：Android Root 后端与已安装的 `com.tailscale.ipn` 共存，Tailscale 不启用出口节点。普通 VpnService 后端不变。

## 本次实现

- Root 不申请 Android VPN 槽位，启动和重建时不再因存在 VPN 网络而返回 `BF-ROOT-OTHER-VPN`。
- BFR6 在用户应用策略之外记录 Tailscale 的基础设施 UID。Tailscale 的传输进程不再被送回 Bifrost 的 TUN；用户其他应用的 allow/exclude 规则仍保留。旧 BFR1–5 日志按原格式清理。
- 在 Bifrost 自有路由表放置 `throw` 路由，将 `100.64.0.0/10`（含 MagicDNS）、`fd7a:115c:a1e0::/48` 和 IPv4 RFC1918 私网地址交还 Android 后续路由选择。Bifrost 不写入 Tailscale 路由表。这些目的地址在 Bifrost 临时封锁期间仍可由系统处理。
- 未安装 Tailscale 时不产生上述例外。每次 Root 健康检查复核基础设施 UID；安装、卸载或 UID 变化会要求通过既有恢复流程重建，避免永久使用旧 UID。
- 辅助进程已失效时，先关闭旧核心并释放 TUN 描述符，再创建新的封锁边界；存活边界仍先封锁再停止核心。停止失败不允许启动第二个核心。准备阶段错误现在也进入恢复退避，并记录失败/完成事件。

### 真机发现的 DNS 补充修复（BFR7 / BFR8）

手机实测发现单纯旁路整个 Tailscale UID 会把它代应用转发的公网 DNS 一并旁路。移动网络下，MagicDNS 曾为 `pbs.twimg.com` 返回异常地址，媒体连续 TLS 失败；只将该 UID 的 TCP/UDP 53 查询接回 Bifrost 后，8 次媒体请求全部成功。因此 BFR7 将 DNS 单独标记，保留 Android 原有标记，并由仅匹配该 UID/标记的规则送入 Bifrost。基础设施 DNS 保留原有拒绝与真实解析策略，不返回供普通应用使用的虚拟地址，避免破坏 Tailscale 自身的连接建立。

Wi-Fi 又暴露了绑定接口的 DNS 套接字问题：即使增加精确 DNS 路由，查询仍发往路由器。BFR8 从当前底层网络读取 DNS 地址，仅对 Tailscale UID 发往这些地址的 TCP/UDP 53 做 DNAT，接入只监听本机的 DNS 入站，由 conntrack 恢复回复来源。规则不匹配 HTTP/HTTPS 管理页面，也不接管任意私网 DNS。IPv6 link-local DNS 延用原有 TPROXY 路径并加入基础设施 UID，保留接口 scope。网络 DNS 列表变化触发边界重建；清理仍按版本化日志逐条删除。Android 的 Tailscale DNS 网络缓存也在边界切换时失效，不改变其 DNS 配置。

BFR1–7 日志仍按旧规则精确清理。BFR8 在 UID 列表后记录 DNS 地址，严格限制数量并校验为 IP 地址。公网加密 DNS 策略、Tailscale MagicDNS 与实际 tailnet 路由分别保留。

BFR9 增加仅匹配基础设施 UID 的 TCP 443 标记，支持当前网络无法直连的 Tailscale HTTPS 控制和 DERP 中继连接。真实重启对照中，完全直连时控制请求反复超时、VPN 接口不建立；加入该例外后建立接口，并经 MagicDNS 成功访问电脑 HTTP 服务。UDP 直连及 NAT 探测继续旁路 Bifrost；私网目的仍服从 throw 路由。HTTPS 中继此时可能多经过代理一跳，不宣称更低延迟或更高吞吐。BFR8 及以前的日志不含新增 HTTPS 规则，按原版本清理。

共存时共享的 IPv6 scoped DNS 入站一律返回真实答案，避免 TPROXY 后 UDP 所有者识别缺失导致 Tailscale bootstrap 收到虚拟地址。普通 TUN 应用查询仍保留虚拟地址策略。显式 `SO_BINDTODEVICE` 的测试程序在私网 IPv4 DNS 上仍有失败；该能力不在已验证共存范围内，不能由 Android `Network.bindSocket` 或真实 Tailscale 成功推断为任意设备绑定应用都受支持。

## 验证

`BifrostRootRecoveryTest` 覆盖恢复顺序、失败停止、UID 与日志编码；`BifrostRootPolicyTest.cpp` 编译并调用真实 C++ 解析器和命令生成器，覆盖 BFR1–6、三种应用策略、非法 UID、精确删除。

`BifrostRootRoutingIntegrationTest.cpp` 只能在 root 的全新 Linux 网络命名空间执行，使用真实 `ip rule` / `ip route` 与生产代码生成的参数。验证双栈、另一 VPN 的独立路由表、MagicDNS 地址、RFC1918 子网、基础设施传输、Bifrost 自有虚拟地址、另一 VPN 路由反复撤销/恢复，以及清理后的路由归属。

这些检查不等于 Android 设备上真实 Tailscale 的长期共存验证，尚需手机运行期日志和实际流量测试。

## 边界与后续性能工作

此实现没有解析任意 VPN 的全量路由。不宣称支持 Tailscale 出口节点、任意公网子网通告、其他 IPv6 私有子网或 Android“阻止未通过 VPN 的连接”锁定策略。IPv4 私网例外只在安装 Tailscale 时启用，其实际出口由系统现有路由决定。

当前 libbox 固定 sing-box 1.13.16。官方 1.15 预发布版本加入完整 Android Root auto_redirect 支持、新 TCP/IP 栈和多队列选项；这些涉及自有 TUN FD、标记、UID、DNS 与清理协议的适配，需要独立迁移验证。不得直接把配置开关加进当前固定内核或宣称已经提速。

参考：
- https://sing-box.sagernet.org/changelog/
- https://sing-box.sagernet.org/configuration/inbound/tun/
- https://www.kernel.org/doc/html/next/networking/tuntap.html
- https://tailscale.com/docs/reference/faq/other-vpns
