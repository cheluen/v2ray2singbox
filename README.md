# V2ray2Singbox 节点转换工具 (自用)

## 项目介绍

V2ray2Singbox 是一个用于将各种代理节点链接（如 vmess、ss、trojan、vless、hysteria2 等）转换为 [sing-box](https://github.com/SagerNet/sing-box) 配置文件的工具。它可以批量处理节点文件，为每个节点创建对应的入站和出站配置，并自动生成路由规则。

## 功能特点

- 支持多种协议的节点转换：
  - VMess
  - Shadowsocks (包括 2022-blake3-aes-256-gcm 加密方式)
  - Trojan
  - VLESS
  - Hysteria2
- 自动为每个节点创建独立的入站端口
- 自动生成对应的路由规则
- 支持自定义配置（用户名、密码、起始端口、监听地址等）
- 支持各种传输协议（ws、tcp、grpc、http等）
- 支持 TLS 配置

## 安装方法

### 环境要求

- Python 3.7+
- 无需额外依赖（核心功能基于Python标准库）

### 安装步骤

1. 下载项目

```bash
git clone https://github.com/cheluen/v2ray2singbox.git
cd v2ray2singbox
```

2. 直接使用

```bash
python v2ray2singbox.py --help
```

### 可选依赖

如果需要导出Clash配置（`--export-clash`功能），需要安装PyYAML：

```bash
pip install PyYAML
# 或者
pip install -r requirements.txt
```

## 使用方法

### 基本用法

1. 准备节点文件

   编辑 `node.txt` 文件，将你的节点链接放入其中，每行一个：

```
vmess://eyJ2IjoiMiIsInBzIjoidGVzdCIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI4MDgwIiwiaWQiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwYWIiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJ0ZXN0LmNvbSIsInBhdGgiOiIvdGVzdCIsInRscyI6InRscyJ9
vless://12345678-1234-1234-1234-123456789012@example.com:443?type=ws&path=/test&security=tls&sni=example.com#test-vless
ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@example.com:8388#test-ss
trojan://password@example.com:443?type=ws&path=/trojan&sni=example.com#test-trojan
```

2. 运行转换工具

```bash
python v2ray2singbox.py
```

3. 使用生成的配置

   程序会生成 `config.json` 文件，可以直接用于 sing-box：

```bash
sing-box run -c config.json
```

### 命令行选项

```bash
# 基本转换
python v2ray2singbox.py -i nodes.txt -o config.json

# 验证节点（不生成配置）
python v2ray2singbox.py --validate-only --verbose

# 同时导出Clash配置
python v2ray2singbox.py --export-clash --clash-output clash.yaml
```

参数说明：
- `-i, --input`: 输入节点文件路径（默认：node.txt）
- `-o, --output`: 输出sing-box配置文件路径（默认：config.json）
- `-c, --config`: 设置文件路径（默认：settings.json）
- `--validate-only`: 仅验证节点，不生成配置文件
- `--export-clash`: 同时导出Clash配置（需要PyYAML）
- `--clash-output`: Clash配置文件输出路径（默认：clash.yaml）
- `--verbose, -v`: 显示详细输出

### 自定义配置

你可以通过修改 `settings.json` 文件来自定义配置：

```json
{
    "username": "root",
    "password": "root",
    "start_port": 30001,
    "listen": "127.0.0.1"
}
```

配置项说明：
- `username`: 入站代理的用户名
- `password`: 入站代理的密码
- `start_port`: 入站代理的起始端口号（每个节点会依次递增）
- `listen`: 入站代理的监听地址（设为空字符串或 `::` 将监听所有地址）

## 支持的协议

### 完全支持的协议
- **VMess** - 支持所有传输协议 (TCP, WebSocket, gRPC, HTTP/2, QUIC)
- **VLESS** - 支持所有传输协议和流控 (XTLS)
- **Shadowsocks** - 支持所有加密方法，包括2022系列
- **Trojan** - 支持所有传输协议
- **Hysteria2** - 支持完整配置
- **TUIC** - 支持v4/v5协议
- **Hysteria** - 支持v1协议
- **SSH** - 支持密码和密钥认证
- **ShadowTLS** - 支持v2/v3协议
- **WireGuard** - 基础支持

### 传输协议支持
- **TCP** - 支持HTTP伪装
- **WebSocket** - 支持早期数据
- **gRPC** - 支持多路模式
- **HTTP/2** - 完整支持
- **QUIC** - 基础支持
- **HTTPUpgrade** - 新协议支持

### TLS特性支持
- **标准TLS** - 完整支持
- **uTLS指纹** - 支持多种指纹
- **Reality** - 支持公钥和短ID
- **ECH** - 实验性支持
- **证书验证** - 可配置跳过

### 加密方法支持
#### Shadowsocks传统加密
- AES-128/192/256-GCM/CFB/CTR
- ChaCha20-IETF-Poly1305
- XChaCha20-IETF-Poly1305

#### Shadowsocks 2022系列
- 2022-blake3-aes-128-gcm
- 2022-blake3-aes-256-gcm
- 2022-blake3-chacha20-poly1305

## 使用方法

### 基本使用

1. 将节点链接放入 `node.txt` 文件中，每行一个节点
2. 运行转换脚本：

```bash
python v2ray2singbox.py
```

3. 生成的 `config.json` 文件即为 sing-box 配置文件

### 命令行选项

```bash
# 基本转换
python v2ray2singbox.py -i nodes.txt -o config.json

# 验证节点（不生成配置）
python v2ray2singbox.py --validate-only -i nodes.txt --verbose

# 同时导出Clash配置
python v2ray2singbox.py --export-clash --clash-output clash.yaml

# 显示详细输出
python v2ray2singbox.py --verbose

# 海外环境优化（从海外访问国内节点）
python v2ray2singbox.py --overseas -i nodes.txt -o config.json
```

### 参数说明
- `-i, --input`: 输入节点文件路径（默认：node.txt）
- `-o, --output`: 输出sing-box配置文件路径（默认：config.json）
- `-c, --config`: 设置文件路径（默认：settings.json）
- `--validate-only`: 仅验证节点，不生成配置文件
- `--export-clash`: 同时导出Clash配置
- `--clash-output`: Clash配置文件输出路径（默认：clash.yaml）
- `--verbose, -v`: 显示详细输出
- `--overseas`: 海外环境优化模式（适用于从海外访问国内节点）

### 新功能特性

#### 🔍 节点验证
- 自动验证节点配置的完整性
- 详细的错误报告和警告信息
- 支持仅验证模式，无需生成配置

#### 📊 配置统计
- 显示各协议节点数量统计
- 配置文件结构分析
- 成功/失败节点统计

#### 🔄 多格式导出
- 原生sing-box配置
- Clash配置导出（实验性）
- 支持自定义输出路径

#### 🛡️ 增强的错误处理
- 健壮的URL解析
- 详细的错误信息
- 自动跳过无效节点

#### ⚡ 性能优化
- 统一的协议解析框架
- 优化的配置生成流程
- 减少重复代码

#### 🌍 海外环境优化
- **海外访问优化**：专门针对从海外访问国内节点的优化
- **多DNS服务器**：使用多个可靠的DNS服务器提高解析成功率
- **连接超时优化**：增加连接超时时间适应跨国网络延迟
- **故障转移机制**：自动在多个节点间切换，提高连接成功率
- **域名解析策略**：优化域名解析策略，优先使用IPv4

## 注意事项

1. 对于 Shadowsocks 的 2022-blake3-aes-256-gcm 加密方式，本工具有特殊处理逻辑，可以正确解析 node.txt 中的特殊格式。
2. 如果节点链接包含中文或特殊字符，请确保节点文件使用 UTF-8 编码保存。
3. 生成的配置文件默认将每个节点的流量分别路由到对应的出站，不包含分流规则。
4. 使用虚拟环境可以避免依赖冲突，建议始终在虚拟环境中运行本工具。

## 常见问题

### Q: 为什么有些节点转换失败？

A: 可能是因为节点链接格式不标准或者包含了工具尚未支持的特殊参数。请检查节点链接格式，或者提交 issue 报告问题。

### Q: 如何同时使用多个节点？

A: 本工具会为每个节点创建独立的入站端口，你可以通过不同的端口使用不同的节点。例如，如果起始端口是 30001，那么第一个节点的端口是 30001，第二个节点的端口是 30002，以此类推。

### Q: 如何修改生成的配置文件？

A: 生成的 config.json 是标准的 sing-box 配置文件，你可以根据 [sing-box 文档](https://sing-box.sagernet.org/) 手动修改它以添加更多功能。

### Q: 如何退出虚拟环境？

A: 在命令行中输入 `deactivate` 即可退出虚拟环境。

## 许可证

本项目采用 MIT 许可证。

## 致谢

- [sing-box](https://github.com/SagerNet/sing-box) - 通用代理平台
- 所有为本项目提供帮助和建议的贡献者