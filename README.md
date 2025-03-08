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

### 依赖环境

- Python 3.6+

### 安装步骤

1. 克隆或下载本仓库

```bash
git clone https://github.com/cheluen/v2ray2singbox.git
cd v2ray2singbox
```

2. 创建并激活虚拟环境（推荐）

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 基本用法

1. 准备节点文件

   创建一个名为 `node.txt` 的文件，将你的节点链接（vmess://、ss://、trojan://、vless://、hysteria2://）按行放入其中。

2. 运行转换工具

```bash
# 确保已激活虚拟环境
python v2ray2singbox.py
```

3. 使用生成的配置

   程序会生成 `config.json` 文件，可以直接用于 sing-box：

```bash
sing-box run -c config.json
```

### 命令行参数

```
python v2ray2singbox.py [-i INPUT] [-o OUTPUT] [-c CONFIG]
```

参数说明：
- `-i, --input`: 输入节点文件路径，默认为 `node.txt`
- `-o, --output`: 输出配置文件路径，默认为 `config.json`
- `-c, --config`: 设置文件路径，默认为 `settings.json`

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

## 支持的节点格式

### VMess

```
vmess://base64编码的json配置
```

### Shadowsocks

```
ss://base64编码的(method:password)@server:port#remarks
```

或

```
ss://base64编码的(method:password@server:port)#remarks
```

### Trojan

```
trojan://password@server:port?sni=example.com&type=ws&path=/path#remarks
```

### VLESS

```
vless://uuid@server:port?security=tls&type=ws&path=/path#remarks
```

### Hysteria2

```
hysteria2://password@server:port?insecure=1&sni=example.com#remarks
```

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