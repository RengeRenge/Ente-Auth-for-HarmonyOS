# Ente Auth for HarmonyOS

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](./LICENSE)

[Ente Auth](https://ente.com/auth) 的 HarmonyOS 原生客户端 —— 端到端加密的双因素认证（2FA）验证器。

本项目是 [ente-io/ente](https://github.com/ente-io/ente) 的第三方移植，非官方版本。基于官方 Web 应用（auth.ente.com）与 ArkTS 原生界面混合构建，账号与数据完全兼容官方服务。

## 功能特性

- **双因素认证码**：支持 TOTP / Steam / 移植自官方的完整验证码展示与搜索
- **端到端加密同步**：通过官方 Ente 账号登录，密钥在本地派生，服务端零知识
- **Argon2 原生加速**：C++（NDK）实现的 Argon2id 密钥派生，登录更快
- **HUKS 硬件级密钥保护**：加密密钥存储于系统级密钥管理服务，不落明文
- **生物识别解锁**：指纹 / 3D 人脸验证本地加密库
- **手表伴侣**：Wear Engine 手表端同步查看验证码（仅查看）
- **原生 ArkTS 界面**：深色模式、多语言（跟随官方翻译）、横竖屏与折叠屏适配

## 架构概览

```
┌─────────────────────────────────────────────┐
│              ArkTS 原生界面                  │
│   (pages/Index.ets — 主界面/登录/设置)        │
├─────────────────────────────────────────────┤
│  service/Bridge.ets  ←→  auth.ente.com (Web) │  混合架构：官方 Web 应用提供核心逻辑
│    JSBridge 注入原生能力（Argon2/生物识别等）   │
├─────────────────────────────────────────────┤
│  service/Huks.ets · Store.ets · Biometrics  │  HUKS 密钥库 / 加密存储 / 生物识别
│  service/Argon2.ets → cpp/ (NDK Argon2id)   │  原生模块
│  service/WearSync.ets → watch/ (Wear Engine) │  手表同步
└─────────────────────────────────────────────┘
```

## 环境要求

| 依赖 | 版本 |
| ---- | ---- |
| DevEco Studio | 5.0+ （推荐 6.0） |
| HarmonyOS SDK | targetSdk 6.0.0 (API 26)，compatibleSdk 5.0.0 (API 12) |
| HarmonyOS 设备 | HarmonyOS NEXT 5.0.0 及以上（手机 / 平板 / 折叠屏） |

## 构建步骤

```bash
# 1. 克隆（含上游参考子模块）
git clone --recurse-submodules https://github.com/RengeRenge/Ente-Auth-for-HarmonyOS.git

# 2. 安装依赖
cd Ente-Auth-for-HarmonyOS/harmony/EnteAuth
ohpm install

# 3. 用 DevEco Studio 打开 harmony/EnteAuth，配置签名
#    File > Project Structure > Signing Configs > 勾选 Automatically generate signature
#    （登录个人华为账号即可自动签名，仓库不包含签名配置）

# 4. 构建 / 运行
hvigorw assembleHap   # 或直接在 DevEco Studio 中 Run
```

> 仓库不包含任何签名材料与签名配置。每位构建者需在本地自动签名，详见上文步骤 3。

## 目录结构

```
.
├── LICENSE                    # AGPL-3.0
├── harmony/EnteAuth/          # HarmonyOS 主工程
│   ├── AppScope/              # 应用级配置与资源
│   ├── entry/                 # 主模块（手机 / 平板 / 折叠屏）
│   │   └── src/main/
│   │       ├── ets/
│   │       │   ├── pages/     # 页面（Index.ets 主界面）
│   │       │   ├── service/   # Bridge / HUKS / Argon2 / 生物识别 / 手表同步
│   │       │   ├── model/     # 数据模型
│   │       │   └── entryability/
│   │       ├── cpp/           # Argon2 原生模块（C++ / CMake）
│   │       └── resources/     # 多语言 / 图片 / 配置
│   ├── watch/                 # 手表伴侣模块（仅查看验证码）
│   ├── scripts/               # i18n 同步脚本（从上游拉取翻译）
│   └── hvigor/                # 构建配置
└── src/ente/                  # 上游 ente-io/ente 子模块（参考用，浅克隆）
```

## 上游与翻译同步

- 上游仓库以浅子模块形式引入（`src/ente`），仅作对照参考，不参与构建。
- 翻译文案通过脚本与官方保持同步：

```bash
cd harmony/EnteAuth
node scripts/sync-i18n.mjs       # 同步官方翻译
node scripts/audit-i18n.mjs      # 校验翻译完整性
```

## 与官方的关系

- 本项目为**社区第三方客户端**，与 ente.io 官方无隶属关系。
- 数据通过官方 API（auth.ente.com）同步，账号可与其他平台官方客户端互通。
- 建议同时关注官方仓库 [ente-io/ente](https://github.com/ente-io/ente)。

## 开源协议

本项目采用 [AGPL-3.0](./LICENSE) 协议开源，与上游 [ente-io/ente](https://github.com/ente-io/ente) 保持一致。

作为 AGPLv3 的衍生作品，任何基于本项目的修改与分发都必须以相同协议开源，且通过网络提供服务时也需向用户提供源代码。
