# Security Policy / 安全策略

## Reporting a Vulnerability / 报告漏洞

**Report privately — do NOT open a public issue.**
**请私下报告，不要开公开 issue。**

- **Preferred / 首选**：GitHub Private Vulnerability Reporting
  （仓库 Security 标签页 → "Report a vulnerability"）
- **Also accepted / 同样接受**：加密邮件发送至 huaitian.behinder@gmail.com，
  使用 GPG 公钥
  `125F 7101 1717 0318 A318  F9C4 7FA3 DE0E 6B42 E01A`（Huai-Tian (Feedback)）

**What to include / 请附**：受影响的版本（见 Releases）或 commit SHA、复现
步骤、影响评估；若涉及线上协议，注明与
[docs/wire-spec.md](docs/wire-spec.md) 的偏差章节。

## Scope / 范围

- Native 密码学核心 `app/src/main/cpp/`：SPAKE2 配对、AEAD 帧格式与终身
  流水号、传输掩码、`.swx` 文件封缄、`sodium_malloc` 守护内存
- JNI 桥（`WaxNative` ↔ `libwax.so`）：密钥跨界与清零纪律
- Android 层：Keystore/Tink 信封与保存态、历史与会话持久化、剪贴板与
  SAF 导出面、配对二维码、FLAG_SECURE / `allowBackup=false` 加固
- 线上协议与测试向量（[docs/wire-spec.md](docs/wire-spec.md)）

Out of scope / 不在范围：README「Honest boundaries / 诚实的边界」已载明的
设计边界——已解锁设备被完全掌控的取证、通信元数据、对端背叛、低熵暗号
——这些是文档化的边界，不是漏洞。

## What to expect / 预期

本项目为非商业研究项目，由个人维护：**尽力而为响应，不承诺时限**。
确认有效的问题会尽快修复并在 GitHub Security Advisories 公告。

## Safe harbor / 安全港

私下报告的善意安全研究不会被追究法律责任。
Good-faith research reported privately will not face legal action.
