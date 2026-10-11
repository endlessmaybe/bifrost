# 源码与构建说明

普通用户直接从 [Releases](https://github.com/endlessmaybe/bifrost/releases/latest) 下载安装包。

## 目录

| 目录 | 内容 |
| --- | --- |
| `repos/bifrost-clients/android-app` | Kotlin / Compose 安卓客户端、VPN 与 Root 运行逻辑 |
| `repos/bifrost-clients/windows-app` | C# / WPF Windows 界面 |
| `repos/bifrost-clients/windows-service` | Windows 服务、Mihomo、路由与网络边界 |
| `repos/bifrost-clients/config-contracts` | 配置、协议与发布契约 |
| `repos/bifrost-infra` | 项目允许公开的构建与安装工具 |
| `build-inputs` | 原始发布源码包中的锁定构建输入与第三方源码 |
| `release-info` | 双平台发布清单、签名、SBOM 与源码清单 |

本仓库从 Android 2.2.41 正式对应源码包展开，将其中的 `clients/` 映射到 `repos/bifrost-clients/`，`infra/` 映射到 `repos/bifrost-infra/`。该包内 Windows 项目版本为 2.2.63。

每个平台的**原始对应源码包**分别在 Releases：`windows-SOURCE-BUNDLE.tar` 与 `android-SOURCE-BUNDLE.tar`。复现特定安装包时使用对应平台原始包；原始路径和哈希由附带的源码清单记录，不能直接用于验证重排目录后的仓库。

## 构建

先阅读 [BUILDING.md](../repos/bifrost-clients/BUILDING.md)、[核心来源](../repos/bifrost-clients/CORE_PROVENANCE.md) 与 [安装信息](../repos/bifrost-clients/INSTALLATION_INFORMATION.md)。使用发布清单锁定的工具链版本。

- Windows：.NET 10、Windows SDK，构建 WPF 与 Windows Service 项目。
- Android：JDK 17、Android SDK 35、NDK 28.2.13676358、项目 Gradle wrapper。最低运行版本 Android 9。
- 协议工具与测试：Node.js 22.5+；仓库本次验证使用本机 Node.js。

安卓 native AAR 与核心是构建产物，由公开脚本及锁定源码生成。官方 APK 使用原签名密钥；自行构建的新签名不能覆盖官方应用。签名私钥由发布者单独管理。

项目测试中部分集成用例依赖独立 Control / Node 工程、完整工具链或真实系统网络权限。公开客户端仓库包含相关接口与源码，但不包含私人服务配置。

## 许可证

客户端 GPLv3。完整文本见 [COPYING](../repos/bifrost-clients/COPYING)。第三方许可见 [THIRD_PARTY_NOTICES.md](../repos/bifrost-clients/THIRD_PARTY_NOTICES.md) 与 `licenses/`。

Control、Node Agent 与私人运维实现遵循项目原有独立许可边界。
