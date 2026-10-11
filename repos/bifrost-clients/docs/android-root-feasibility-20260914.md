# Android 快捷连接、通知网速与 Root 模式可行性评估

日期：2026-09-14。范围：用户两张截图、当前 2.2.12 代码、USB 连接手机的只读检查、Android 与上游官方资料。本文件是评估与实现建议，不表示相关功能已开发、安装或发布。本轮未改变手机网络路由、防火墙、SELinux、账号或应用安装状态。

## 判断

| 想法 | 判断 | 条件 |
|---|---|---|
| HyperOS 控制中心添加 Bifrost 图标，一键连接 | 可实现，无需 Root | 使用标准 TileService；用户首次添加磁贴并完成账号登记及系统 VPN 授权；具体布局由系统控制 |
| Bifrost 常驻通知显示实时上传、下载 | 可实现，无需 Root | 从现有内核计数分出后台轻量速率快照，节流更新同一条通知，不能复用退后台后停止更新的界面指标 |
| Root 模式关闭界面后继续运行 | 有可行的实现路径 | 独立 Root 网络进程与明确的管理接口；应用界面、控制面、底层接管职责拆分 |
| Root 模式不显示系统 VPN 图标 | 有条件可实现 | 真正脱离 VpnService，用 Root TUN/透明代理接管；继续使用 VpnService 时不能通过普通应用 API 控制系统 VPN 标志 |
| 不被划掉后台轻易终止 | 可作为验收目标 | 须在该 HyperOS 实测清理行为、长时间锁屏及 Root 权限变化 |
| 完全不可见、任何情况下只能打开应用终止 | 无法作绝对保证，也不应成为故障处理约束 | 重启、底层崩溃、Root 撤权、卸载更新和管理员停止仍可能终止；还需尊重后台撤销及账号到期 |

“一键激活”按一键连接理解，不是自动使用注册码。建议未连接时磁贴发起连接，已连接时打开应用状态页；这与用户希望进入应用再主动停止的习惯一致。长按进入应用设置。首次账号未登记、权限尚未授予或锁屏要求解锁时，跳转完成相应步骤。不能把系统的首次确认当作可以静默跳过的环节。[Android 官方磁贴文档](https://developer.android.com/develop/ui/views/quicksettings-tiles)

## 连接手机的实测条件

- 型号标识 24117RK2CC，产品 zorn。
- Android 16 / API 36，系统版本 OS3.0.307.0.WOKCNXM。
- 当前 Bifrost 为 2.2.12（20212），target SDK 35。
- 内核 6.1.138-android14-11-g965475777129-mi。
- su 返回 30.7:MAGISKSU；只读命令实际获得 uid=0、u:r:magisk:s0。
- SELinux 为 Enforcing。
- 存在 /dev/tun；iptables、ip6tables 均为 1.8.11 legacy；IPv4/IPv6 目标列表可见 TPROXY、REDIRECT、MARK、NFQUEUE。
- 在本次 su 环境的 PATH 中未找到 nft 命令；这不等于断言内核没有 nftables 功能。

这些证据说明本机具备开展 Root 接管原型验证的基础。尚未验证 Bifrost 应用 UID 自身的 Root 授权、完整双栈流量接管、SELinux 访问链、断开清理或长时间后台运行。ADB shell 的 Root 成功不能替代应用自己的授权验证。

## 代码中已确认的情况

1. AndroidManifest.xml 目前只有 BifrostVpnService，没有 TileService。已有 Bifrost 单色图标，可用于系统磁贴，不需要更改应用界面风格。
2. BifrostTrafficTelemetry.kt 中，CommandClient 每秒提供流量数据，但 accept() 在 BifrostAppVisibility.visible 为 false 时提前返回，避免后台生成图表和格式化字符串。这是既有性能设计。新增通知应保存少量原始速率数据，避免为了通知重新开启后台图表计算。
3. BifrostVpnService.kt 的通知只显示传入状态文本，探测结束会写入“线路探测已完成”，尚未显示实时速率。建议连接正常时显示“已连接 · 当前线路”及“↑ 上传 / ↓ 下载”，阻断、恢复中或已断开时以真实状态优先，不能显示过期速度误导用户。
4. BifrostCoreAdapter 和 BifrostLibboxPlatform 当前直接依赖 VpnService；TUN 创建、上游 socket protect、应用分流、网络切换和阻断接口均与之耦合。增加一个 su 调用不会解除这些依赖。
5. 当前锁定 sing-box 1.13.16 与 sing-tun 0.8.12-0.20260727151122-3a09076491df+bifrost-detach。已读取随版本保存的源码：Android auto_redirect 分支使用 IPv4 与 iptables；同版本文档明确其 Android 自动重定向为简单 IPv4 TCP 转发。**此限制仅指拟用于 Root 模式的自动重定向分支，不代表当前 VpnService/TUN 模式只有 TCP 能力。**不能把最新版网站所说的完整 Android 支持推定为当前包已支持，也不能把单个自动重定向开关当成整套双栈 Root 接管方案。[锁定版本上游文档](https://github.com/SagerNet/sing-box/blob/v1.13.16/docs/configuration/inbound/tun.md)

通知建议默认约 2 秒刷新一次，复用同一通知 ID、静默更新；息屏降低频率，重新亮屏及时刷新。计数范围应明确是 Bifrost 内核统计流量，不宣传为手机全接口网速，也不执行额外测速下载。Android 对通知更新有频率限制。[Android 通知更新文档](https://developer.android.com/develop/ui/compose/notifications/create-notification)

## Root 方案的边界与实现重点

建议提供默认普通 VPN 模式与用户主动启用的 Root 模式，使用相同的账号、签名配置、选线策略和状态原则。Root 模式可以让界面关闭后由独立服务继续转发；磁贴和可选网速通知显示其读回状态。Root 服务可以使用具有独立生命周期的 daemon 机制，但该机制同样有卸载、更新与主动停止的生命周期。[libsu RootService 官方文档](https://topjohnwu.github.io/libsu/com/topjohnwu/superuser/ipc/RootService.html)

系统 VPN 标志来自 Android 管理的 VPN 连接。可行方向是 Root 自行创建 TUN/透明代理接管，从而不建立 VpnService 连接。只隐藏 SystemUI 图标不会改变连接管理和进程生命周期；也不能保证其他应用无法通过 Root 状态、流量出口或网络特征检测使用代理。[Android VPN 用户体验与生命周期](https://developer.android.com/develop/connectivity/vpn)

必须同时解决：

- TCP、UDP/QUIC、IPv4、IPv6、DNS 的一致接管；对当前内核不足的部分，选择受验证的适配或升级方案，不能仅打开 IPv4 TCP 重定向。
- 仅拥有并管理 Bifrost 自己的规则、路由表、标记及进程，避免覆盖系统、其他代理、热点和双卡规则；避免代理出口再次进入代理造成回环。
- 用户打开应用时可靠连接到原有守护进程并读取实际状态，不根据前台进程是否存活判断账号/连接。
- 用户停止、卸载、更新、Root 失效、网络切换、内核异常时，有可验证的规则撤销与故障恢复路径；不能留下永久断网状态。
- 保持应用账号及 Android Keystore 的身份边界；不能假设 Root UID 可无条件直接使用普通应用 UID 的 Keystore 身份。
- 后台账号撤销、到期和授权刷新仍有效。界面关闭不能使旧授权在底层无限续用。
- 权限管理器和系统管理员保持紧急停止能力。不以隐藏进程、绕过所有终止渠道或一直自动拉起作为稳定性保证。

用户可以把“日常只从应用内主动停止”定义为操作习惯，但不能要求所有退出条件都依赖应用按钮。Android 的普通前台服务本身也允许用户从系统任务管理入口停止。[Android 用户主动停止机制](https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping)

## 建议顺序

1. 先单独交付快捷连接和通知网速：复用当前连接事务，验证权限、账号、后台速度和错误状态，避免改变稳定的数据通路。
2. Root 模式先作为明确标识的实验选项，在这台已 Root 手机验证；不自动给其他用户切换。
3. 验收覆盖移动网络/Wi-Fi 切换、锁屏、最近任务划除、短时断网、TCP/UDP/IPv6/DNS、账号撤销、更新卸载和规则清理。完成长时间运行与原始图片/视频场景后，再评估进入默认稳定功能。

原始只读证据保存在 H:/CodexTemp/work/bifrost-android-root-assessment-20260914：phone-baseline.json、phone-root-readonly.json、pinned-root-support.json。

## 补充：双端 UDP、QUIC 与 IPv6 的现状

按当前 2.2.12 编译器与路由代码核对，不能把内核具备某协议能力写成所有出口、网站及场景均已经实测成功。

| 能力 | 当前 Android VpnService 模式 | 当前 Windows 模式 |
|---|---|---|
| TCP | 已有数据通路 | 已有数据通路 |
| UDP | TUN/gVisor 接管；Xray 桥接模式明确路由 tcp,udp | Mihomo VMess 节点明确 udp=true；国家 SOCKS5 出口受其 udp 能力字段限制 |
| QUIC / HTTP/3 | 属于 UDP 流量，存在转发路径；没有统一拒绝 UDP/443 的规则 | 开启 QUIC 嗅探，服务域名与 HTTPS 使用同组策略；没有统一拒绝 UDP/443 的规则 |
| IPv6 | 配置双栈 TUN 地址与路由，但通常 DNS strategy=ipv4_only；IPv6 字面量被接管不等于所有出口 IPv6 已可用 | 全局与 DNS 都明确 ipv6=false，TUN 配置 IPv4；不是已启用的完整双栈代理 |

Windows 证据：windows-service/MihomoConfigCompiler.cs 的全局/DNS ipv6=false、QUIC 嗅探和 TUN；MihomoProviderCompiler.cs 的 udp 字段；MihomoPolicyCompiler.cs 的域名规则。Android 证据：BifrostConfigCompiler.kt 的 DNS 策略、双栈 TUN，BifrostLibboxPlatform.kt 的双栈地址/路由配置，BifrostXrayConfigCompiler.kt 的 tcp,udp 路由。

QUIC 转发代码存在，仍要求选定源站、国家出口及目标支持 UDP；不能宣称“所有连接当前都使用 QUIC”。上述 IPv6 设置也说明“双端原则统一”不等于“双端 IPv6 能力已全部开启”。这次评估没有切换现有 IPv6 配置。

## 补充：后台自动更新

用户希望减少长期不升级的情况。结论：可以实现自动检查/下载，并在系统允许时免确认安装；普通 Android 并非一律需要 Root 才能做到自更新，但不能承诺覆盖所有系统与权限状态。

Android 12 / API 31 起，PackageInstaller 支持 USER_ACTION_NOT_REQUIRED。官方自更新条件包括安装权限授权、安装目标的 target SDK 达标、安装器为受认可的更新方或更新自身、声明 UPDATE_PACKAGES_WITHOUT_USER_ACTION 等。系统仍可能返回 STATUS_PENDING_USER_ACTION，必须保留确认回退。该手机 Android 16 对此要求 target SDK 至少 34，Bifrost 当前 target SDK 35 满足这一项；其他条件及 HyperOS 实际行为尚未做安装验证。[Android PackageInstaller 官方条件](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int))

当前代码尚未实现完整后台静默更新：

- MainActivity 的检查默认不下载包，安装由用户操作触发。
- BifrostUpdateManager.installVerifiedApk() 明确设置 USER_ACTION_REQUIRED。
- 清单没有 UPDATE_PACKAGES_WITHOUT_USER_ACTION，也没有 MY_PACKAGE_REPLACED 恢复接收器。
- 更新前会停止 VPN；更新后的重连意图由 MainActivity.resumeAfterPackageUpdate() 处理，仍依赖再次打开界面，不能直接复用于无界面后台更新。

建议流程：用户启用自动更新并完成系统安装授权 → 后台限频检查并分散请求 → 先下载完整包并校验签名/摘要/包名/版本 → 等待合适的空闲窗口 → 记录原账号及连接意图 → 安装并由包替换后的后台入口恢复 → 验证实际版本与连接状态。确认安装不可避免时使用通知提示，不能先无限期断开 VPN 等待用户确认。安装失败应结束更新锁并恢复原运行状态。

Root 可为用户明确授权的静默安装提供额外路径，但更新依然涉及应用/daemon 生命周期。不能保证 APK 整包替换毫无断线；官方默认会结束包的运行进程，setDontKillApp 的例外主要针对继承安装中增加 split，并非本项目单 APK 完整升级的通用无中断开关。[Android 安装参数](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setDontKillApp(boolean))

稳定性建议：采用小批量验证后逐步开放自动更新，避免一个坏包立刻覆盖所有用户；常规更新等待空闲期，关键兼容性升级明确期限。协议最低版本要求与自动安装能力分开管理，不能靠注销用户账号来推动升级。已有 2.2.12 用户仍需先升级一次到具备新机制的版本，才能使用后续自更新能力。本轮仅评估，未修改升级器、权限清单或发布策略。
