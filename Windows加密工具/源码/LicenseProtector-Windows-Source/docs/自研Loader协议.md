# 自研 LPBC / Loader 协议

本项目的自研保护链分为 Encoder、Linux Agent 和 PHP Loader 三个边界。当前仓库实现 LPBC v1 容器、完整 PHP 源码 Encoder、Python Agent 和 PHP 扩展源码。扩展源码尚未在本 Windows 环境编译验证，必须在目标 Linux/PHP ABI 上构建集成测试。

## LPBC v1

`.lpbc` 是版本化二进制容器，不使用 Zend opcode。普通交付使用 `php-source-v1`：Loader 在 PHP 进程内存中调用 Zend 编译器执行，绝不把明文写回磁盘。`ir-v1` 仍可用于实验性小程序，但普通 Hyperf 文件不走该路径。

```text
MAGIC       5 bytes: LPBC\\x01
HEADER_LEN  uint32 big-endian
HEADER      UTF-8 canonical JSON
NONCE       12 bytes
CIPHERTEXT  AES-256-GCM(payload, header as AAD)
SIGNATURE   64 bytes Ed25519(signature over every preceding byte)
```

Header 至少包含：

```json
{
  "algorithm": "AES-256-GCM",
  "format_version": 1,
  "path": "app/Service/Payment.php",
  "payload_type": "php-source-v1",
  "payload_sha256": "..."
}
```

运行主密钥由 Agent 保存，不得放在交付目录。Encoder 通过 `agent-keygen` 生成密钥，再使用 `encode --runtime-key` 编码。每个文件的 AES 密钥由 Agent 主密钥和相对路径通过 HMAC-SHA256 独立派生；密钥指纹会写入签名的 `protected/lpbc/manifest.json`，密钥本身不会进入清单。Loader 通过受 Unix 权限保护的本机 Socket 请求当前文件，Agent 在服务器侧完成 LPBC 验签和 AES-GCM 解密，仅返回当前授权载荷；主密钥与派生密钥不会通过 Socket 返回，因此 PHP 服务账号与 Agent socket 权限仍必须严格隔离。

## Agent 协议

Agent 只监听 Unix Socket，每行一个 JSON 请求和响应。请求格式：

```json
{
  "protocol": "LP-AGENT-1",
  "op": "authorize",
  "host": "customer.example.com",
  "path": "protected/lpbc/app/Service/Payment.lpbc",
  "manifest_sha256": "..."
}
```

响应成功时返回协议版本、文件摘要、源路径、载荷类型和当前文件的短生命周期 `payload_b64`。Agent 在服务器侧完成 License、manifest、LPBC 签名校验和 AES-GCM 解密，运行主密钥与派生密钥不会通过 Socket 返回。生产 Loader 应将 Socket 权限限制为 PHP 服务用户，并使用 systemd 以独立低权限用户运行 Agent。

## PHP Loader 当前边界

扩展会验证厂商 Ed25519 容器签名和 `manifest.sig`，通过 Unix Socket 请求 Agent，在进程内存中调用 Zend 编译器执行 PHP；明文不会写入磁盘，也不会使用用户层 `eval()`。Agent 返回的当前 PHP 载荷仍能被有权限调试 PHP 进程或访问 socket 的本机管理员提取，Agent/socket 权限隔离是必要条件，但不能抵御客户 root。

该扩展尚未在 Linux/PHP 目标 ABI 编译测试。必须按目标 PHP 小版本和 CPU 架构分别构建并运行集成测试，未经目标环境验证的产物不能用于生产。
