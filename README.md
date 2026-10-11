# Bifrost

Bifrost 是 Windows 和 Android 网络代理客户端，支持智能选线、全局代理与 SmartGate 国家出口。

**[下载安装包](https://github.com/endlessmaybe/bifrost/releases/latest) · [完整中文使用说明](docs/USER_GUIDE.md) · [源码与构建说明](docs/BUILD.md)**

## 下载

| 平台 | 版本 | 选择 |
| --- | --- | --- |
| Windows x64 | **2.2.63** | `Bifrost-Offline-Setup-2.2.63-r1790830096-Windows-x64.exe` |
| 安卓手机 | **2.2.41** | 通常选择 `Bifrost-Android-2.2.41-arm64-v8a.apk`；红米 K80 使用此包 |
| 旧款 32 位安卓 | **2.2.41** | `Bifrost-Android-2.2.41-armeabi-v7a.apk` |
| x86_64 安卓设备 / 模拟器 | **2.2.41** | `Bifrost-Android-2.2.41-x86_64.apk` |

安卓最低要求 Android 9。Windows 包面向 64 位 Windows，安装时按提示授权管理员权限。

## 五步使用

1. 下载对应安装包并安装。
2. 打开 **设置 → 设备与账户**。
3. 首次使用填邀请码；已有账号用恢复码加入。
4. 点击 **更新节点**，选择 **智能选线**。
5. 点击 **连接**，打开网页确认可访问。

邀请码由管理员提供。安装包本身不包含可直接使用的私人节点与账号。

## 三种模式

| 模式 | 用途 |
| --- | --- |
| 智能选线 | 日常使用；自动选择当前源站的可用线路 |
| 全局代理 | 需要统一走代理时使用 |
| SmartGate | 手动固定一个国家 / 地区出口 |

**更新节点**刷新线路配置；**软件更新**升级程序。电脑和手机版本号独立。

## 源码

- [Windows 桌面界面](repos/bifrost-clients/windows-app)
- [Windows 后台服务](repos/bifrost-clients/windows-service)
- [Android 客户端](repos/bifrost-clients/android-app)
- [公开构建与安装脚本](repos/bifrost-infra)
- [发布信息与 SBOM](release-info)
- [许可证与第三方说明](repos/bifrost-clients/THIRD_PARTY_NOTICES.md)

客户端以 GPLv3 发布。各平台原始对应源码包在 Releases 中下载；仓库保留 Android 2.2.41 发布源码包中的双端源码，Windows 项目版本为 2.2.63。项目公开源码规则将 Control、Node Agent 和私人运维实现保留在独立私有边界。

GitHub 提供源码和下载。客户端现有账号、节点与内置自动更新仍由原 Bifrost 服务提供。
