#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import base64
import urllib.parse
import uuid
import argparse
from typing import Dict, List, Any, Optional, Tuple
from abc import ABC, abstractmethod


class ProtocolParser(ABC):
    """协议解析器基类"""

    @abstractmethod
    def can_parse(self, url: str) -> bool:
        """检查是否能解析此URL"""
        pass

    @abstractmethod
    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析URL并返回sing-box出站配置"""
        pass


class ShadowsocksParser(ProtocolParser):
    """Shadowsocks协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('ss://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析ss链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[5:]  # 移除 ss://

            # 处理有无@符号的情况
            if '@' in url_content:
                # 格式: ss://BASE64(method:password)@server:port#remarks
                auth_str, server_port = url_content.split('@', 1)

                # 处理可能的base64编码
                try:
                    decoded_auth = base64.b64decode(auth_str).decode('utf-8')
                    method, password = decoded_auth.split(':', 1)
                except:
                    # 可能已经是明文
                    method, password = auth_str.split(':', 1)

                # 处理服务器和端口
                if '#' in server_port:
                    server_port, _ = server_port.split('#', 1)

                server, port = server_port.rsplit(':', 1)
            else:
                # 格式: ss://BASE64(method:password@server:port)#remarks
                if '#' in url_content:
                    url_content, _ = url_content.split('#', 1)

                # 解码
                try:
                    decoded = base64.b64decode(url_content).decode('utf-8')
                except:
                    # 尝试添加填充
                    padding = 4 - len(url_content) % 4
                    if padding < 4:
                        url_content += '=' * padding
                    decoded = base64.b64decode(url_content).decode('utf-8')

                # 解析格式 method:password@server:port
                auth, server_port = decoded.split('@', 1)
                method, password = auth.split(':', 1)
                server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "shadowsocks",
                "server": server,
                "server_port": int(port),
                "method": method,
                "password": password
            }

            # 处理2022-blake3-aes-256-gcm特殊情况
            if method == '2022-blake3-aes-256-gcm':
                outbound = self._handle_2022_blake3(outbound, password)

            # 处理插件
            if ';' in server:
                outbound = self._handle_plugins(outbound, server)

            return outbound

        except Exception as e:
            print(f"解析ss链接失败: {e}")
            return None

    def _handle_2022_blake3(self, outbound: Dict[str, Any], password: str) -> Dict[str, Any]:
        """处理2022-blake3-aes-256-gcm加密方式"""
        if ':' in password and password.endswith('='):
            try:
                key_b64, salt_b64 = password.split(':', 1)
                key = base64.b64decode(key_b64).decode('utf-8')
                salt = base64.b64decode(salt_b64).decode('utf-8')
                outbound["password"] = f"{key}:{salt}"
            except Exception:
                pass
        elif ':' not in password:
            try:
                decoded = base64.b64decode(password).decode('utf-8')
                if ':' in decoded:
                    parts = decoded.split(':', 2)
                    if len(parts) >= 3:
                        _, key_b64, salt_b64 = parts
                        try:
                            key = base64.b64decode(key_b64).decode('utf-8')
                            salt = base64.b64decode(salt_b64).decode('utf-8')
                            outbound["password"] = f"{key}:{salt}"
                        except Exception:
                            outbound["password"] = f"{key_b64}:{salt_b64}"
                    elif len(parts) == 2:
                        key, salt = parts
                        outbound["password"] = f"{key}:{salt}"
                else:
                    # 生成随机密码作为fallback
                    import secrets
                    random_key = secrets.token_hex(16)
                    random_uuid = str(uuid.uuid4())
                    outbound["password"] = f"{random_key}:{random_uuid}"
            except Exception:
                # 生成随机密码作为fallback
                import secrets
                random_key = secrets.token_hex(16)
                random_uuid = str(uuid.uuid4())
                outbound["password"] = f"{random_key}:{random_uuid}"

        return outbound

    def _handle_plugins(self, outbound: Dict[str, Any], server: str) -> Dict[str, Any]:
        """处理SS插件"""
        server_parts = server.split(';')
        outbound["server"] = server_parts[0]

        plugin_parts = server_parts[1:]
        plugin_str = ';'.join(plugin_parts)

        if 'plugin=' in plugin_str:
            plugin_params = dict(item.split('=') for item in plugin_str.split(';') if '=' in item)
            plugin = plugin_params.get('plugin', '')

            if plugin == 'obfs-local':
                outbound["plugin"] = "obfs"
                outbound["plugin_opts"] = {
                    "mode": plugin_params.get('obfs', 'http'),
                    "host": plugin_params.get('obfs-host', '')
                }
            elif plugin == 'v2ray-plugin':
                v2ray_opts = plugin_params.get('plugin-opts', '')
                if v2ray_opts:
                    opts_dict = dict(item.split('=') for item in v2ray_opts.split(';') if '=' in item)
                    outbound["plugin"] = "v2ray-plugin"
                    outbound["plugin_opts"] = {
                        "mode": opts_dict.get('mode', 'websocket'),
                        "tls": opts_dict.get('tls', 'false') == 'true',
                        "host": opts_dict.get('host', ''),
                        "path": opts_dict.get('path', '/')
                    }

        return outbound


class VmessParser(ProtocolParser):
    """VMess协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('vmess://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析vmess链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            b64_content = url[8:]  # 移除 vmess://

            # 处理base64填充
            padding = 4 - len(b64_content) % 4
            if padding < 4:
                b64_content += '=' * padding

            try:
                decoded = base64.b64decode(b64_content).decode('utf-8')
                vmess_info = json.loads(decoded)
            except:
                decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                vmess_info = json.loads(decoded)

            outbound = {
                "type": "vmess",
                "server": vmess_info.get('add', ''),
                "server_port": int(vmess_info.get('port', 0)),
                "uuid": vmess_info.get('id', ''),
                "security": vmess_info.get('scy', 'auto'),
                "alter_id": int(vmess_info.get('aid', 0)),
                "packet_encoding": "packetaddr"  # VMess使用packetaddr
            }

            # 处理传输协议
            transport_type = vmess_info.get('net', '')
            if transport_type:
                transport = self._build_transport(transport_type, vmess_info)
                if transport:
                    outbound["transport"] = transport

            # 处理TLS
            if vmess_info.get('tls') == 'tls':
                tls = {
                    "enabled": True,
                    "server_name": vmess_info.get('sni', vmess_info.get('host', ''))
                }

                if vmess_info.get('verify_cert_chain', True) is False or vmess_info.get('allowInsecure', False):
                    tls["insecure"] = True

                outbound["tls"] = tls

            return outbound

        except Exception as e:
            print(f"解析vmess链接失败: {e}")
            return None

    def _build_transport(self, transport_type: str, vmess_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            transport = {
                "type": "ws",
                "path": vmess_info.get('path', '/')
            }
            if 'host' in vmess_info and vmess_info.get('host'):
                transport["headers"] = {"Host": vmess_info['host']}

            # VMess WebSocket需要early_data配置（根据v2ray-agent脚本）
            transport["max_early_data"] = 2048
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"

            return transport

        elif transport_type == 'tcp':
            transport = {"type": "tcp"}
            if vmess_info.get('type') == 'http':
                transport["header"] = {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [vmess_info.get('path', '/')]
                    }
                }
                if 'host' in vmess_info and vmess_info.get('host'):
                    transport["header"]["request"]["headers"] = {"Host": [vmess_info['host']]}
            return transport

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": vmess_info.get('path', ''),
                "multi_mode": False
            }

        elif transport_type == 'quic':
            return {"type": "quic"}

        elif transport_type == 'h2':
            return {
                "type": "http",
                "host": [vmess_info.get('host', '')],
                "path": vmess_info.get('path', '/')
            }

        return None


class TrojanParser(ProtocolParser):
    """Trojan协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('trojan://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析trojan链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[9:]  # 移除 trojan://

            if '@' not in url_content:
                return None

            password, server_info = url_content.split('@', 1)

            # 处理查询参数和备注
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_dict = dict(item.split('=') for item in params.split('&') if '=' in item)
            else:
                if '#' in server_info:
                    server_port, _ = server_info.split('#', 1)
                else:
                    server_port = server_info

            # 解析服务器和端口
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": params_dict.get('sni', params_dict.get('host', server)),
                    "insecure": False
                }
            }

            # 处理TLS安全选项
            if params_dict.get('allowInsecure', '0') == '1' or params_dict.get('insecure', '0') == '1':
                outbound["tls"]["insecure"] = True

            # 处理传输协议
            transport_type = params_dict.get('type', '')
            if transport_type:
                transport = self._build_transport(transport_type, params_dict)
                if transport:
                    outbound["transport"] = transport

            return outbound

        except Exception as e:
            print(f"解析trojan链接失败: {e}")
            return None

    def _build_transport(self, transport_type: str, params_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            ws = {"type": "ws", "path": params_dict.get('path', '/')}
            if 'host' in params_dict and params_dict.get('host'):
                ws["headers"] = {"Host": params_dict['host']}
            return ws

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": params_dict.get('serviceName', ''),
                "multi_mode": False
            }

        return None


class VlessParser(ProtocolParser):
    """VLESS协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('vless://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析vless链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[8:]  # 移除 vless://

            if '@' not in url_content:
                return None

            uuid_str, server_info = url_content.split('@', 1)

            # 处理备注信息
            if '#' in server_info:
                server_info, remark = server_info.split('#', 1)
                remark = urllib.parse.unquote(remark)

            # 处理查询参数
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_list = params.split('&')
                for item in params_list:
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params_dict[k] = urllib.parse.unquote(v)
            else:
                server_port = server_info

            # 解析服务器和端口
            if ':' not in server_port:
                return None

            server, port = server_port.rsplit(':', 1)

            # 创建基础出站配置
            outbound = {
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": uuid_str
            }

            # 处理flow字段 - 只有非空值才添加
            flow = params_dict.get('flow', '')
            if flow and flow.strip():
                outbound["flow"] = flow

            # 处理安全类型
            security = params_dict.get('security', 'none')
            if security == 'tls':
                outbound["tls"] = self._build_tls_config(params_dict, server)

            # 处理传输协议
            transport_type = params_dict.get('type', '')
            if transport_type:
                transport = self._build_transport(transport_type, params_dict)
                if transport:
                    outbound["transport"] = transport

                    # 根据协议类型设置正确的packet_encoding
                    # VLESS使用xudp编码
                    outbound["packet_encoding"] = "xudp"

            return outbound

        except Exception as e:
            print(f"解析vless链接失败: {e}")
            return None

    def _build_tls_config(self, params_dict: Dict[str, Any], server: str) -> Dict[str, Any]:
        """构建TLS配置"""
        tls = {
            "enabled": True,
            "server_name": params_dict.get('sni', params_dict.get('host', server)),
            "insecure": False
        }

        # 处理跳过证书验证
        if params_dict.get('allowInsecure', '0') == '1' or params_dict.get('insecure', '0') == '1':
            tls["insecure"] = True

        # 处理指纹
        if 'fp' in params_dict and params_dict.get('fp'):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": params_dict.get('fp', 'chrome')
            }

        return tls

    def _build_transport(self, transport_type: str, params_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            # WebSocket配置 - 智能兼容V2Ray和Xray服务器
            transport = {
                "type": "ws",
                "path": params_dict.get('path', '/')
            }

            # 设置Host头
            if 'host' in params_dict and params_dict.get('host'):
                transport["headers"] = {
                    "Host": params_dict['host']
                }

            # 智能early_data配置：
            # 1. 如果URL中有ed参数，说明服务器支持early_data，按Xray模式配置
            # 2. 如果没有ed参数，使用sing-box默认模式（通过path发送）
            if 'ed' in params_dict:
                # Xray兼容模式
                try:
                    transport["max_early_data"] = int(params_dict['ed'])
                except ValueError:
                    transport["max_early_data"] = 2048
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"

            return transport

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": params_dict.get('serviceName', params_dict.get('path', '')),
                "multi_mode": False
            }

        elif transport_type == 'tcp':
            return {"type": "tcp"}

        elif transport_type == 'http':
            return {
                "type": "http",
                "host": [params_dict.get('host', '')],
                "path": params_dict.get('path', '/')
            }

        return None


class Hysteria2Parser(ProtocolParser):
    """Hysteria2协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('hysteria2://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析hysteria2链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[12:]  # 移除 hysteria2://

            if '@' not in url_content:
                return None

            auth, server_info = url_content.split('@', 1)

            # 处理备注信息
            if '#' in server_info:
                server_info, remark = server_info.split('#', 1)

            # 处理查询参数
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_list = params.split('&')
                for item in params_list:
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params_dict[k] = urllib.parse.unquote(v)
            else:
                server_port = server_info

            # 解析服务器和端口
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "hysteria2",
                "server": server,
                "server_port": int(port),
                "password": auth,
                "tls": {
                    "enabled": True,
                    "server_name": params_dict.get('sni', server),
                    "insecure": False
                }
            }

            # 处理TLS安全选项
            if params_dict.get('insecure', '0') == '1':
                outbound["tls"]["insecure"] = True

            # 处理其他参数
            if 'obfs' in params_dict:
                outbound["obfs"] = params_dict['obfs']

            if 'obfs-password' in params_dict:
                outbound["obfs_password"] = params_dict['obfs-password']

            # 添加带宽控制
            if 'up' in params_dict:
                try:
                    outbound["up_mbps"] = int(params_dict['up'])
                except ValueError:
                    pass

            if 'down' in params_dict:
                try:
                    outbound["down_mbps"] = int(params_dict['down'])
                except ValueError:
                    pass

            return outbound

        except Exception as e:
            print(f"解析hysteria2链接失败: {e}")
            return None


class V2raySingboxConverter:
    def __init__(self, config_file: str = 'settings.json'):
        # 默认配置
        self.default_settings = {
            'username': 'root',
            'password': 'root',
            'start_port': 30001,
            'listen': '127.0.0.1'
        }

        # 尝试加载配置文件
        self.settings = self.load_settings(config_file)

        # 初始化协议解析器
        self.parsers = [
            ShadowsocksParser(),
            VmessParser(),
            TrojanParser(),
            VlessParser(),
            Hysteria2Parser()
        ]

        # 初始化sing-box配置模板
        self.singbox_config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "inbounds": [],
            "outbounds": [],
            "route": {
                "rules": [],
                "final": "direct"
            }
        }
    
    def load_settings(self, config_file: str) -> Dict[str, Any]:
        """加载设置文件，如果不存在则创建默认设置"""
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}，使用默认配置")
                return self.default_settings
        else:
            # 创建默认配置文件
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.default_settings, f, indent=4, ensure_ascii=False)
            print(f"已创建默认配置文件: {config_file}")
            return self.default_settings
    
    def parse_nodes(self, node_file: str) -> List[str]:
        """解析节点文件，提取有效节点"""
        nodes = []
        
        try:
            with open(node_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                # 跳过空行和不包含://的行（通常是分类标题）
                if line and '://' in line:
                    nodes.append(line)
        except Exception as e:
            print(f"解析节点文件失败: {e}")
        
        return nodes

    def _clean_empty_fields(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """清理配置中的空字段"""
        cleaned = {}
        for key, value in config.items():
            # 跳过空值、空字符串、空字典和空列表
            if value is not None and value != '' and value != {} and value != []:
                if isinstance(value, dict):
                    cleaned_dict = self._clean_empty_fields(value)
                    if cleaned_dict:
                        cleaned[key] = cleaned_dict
                elif isinstance(value, str) and value.strip():
                    # 只保留非空字符串
                    cleaned[key] = value
                elif not isinstance(value, str):
                    # 保留非字符串类型的值
                    cleaned[key] = value
        return cleaned

    def create_inbound(self, tag: str, port: int) -> Dict[str, Any]:
        """创建入站配置"""
        listen = self.settings.get('listen', '::')
        # 如果监听地址为空，则使用::允许所有连接
        if not listen:
            listen = '::'
            
        return {
            "type": "mixed",
            "tag": tag,
            "listen": listen,
            "listen_port": port,
            "users": [
                {
                    "username": self.settings.get('username', 'root'),
                    "password": self.settings.get('password', 'root')
                }
            ]
        }
    
    def convert_node(self, node_url: str) -> Optional[Dict[str, Any]]:
        """根据节点URL类型调用相应的解析函数"""
        for parser in self.parsers:
            if parser.can_parse(node_url):
                print(f"    🔍 使用 {parser.__class__.__name__} 解析")
                result = parser.parse(node_url)
                if result:
                    print(f"    ✅ 解析成功")
                else:
                    print(f"    ❌ 解析失败")
                return result

        protocol_type = node_url.split('://')[0] if '://' in node_url else 'unknown'
        print(f"    ❌ 不支持的节点类型: {protocol_type}")
        return None



    def generate_config(self, node_file: str, output_file: str = 'config.json') -> bool:
        """生成sing-box配置文件"""
        try:
            # 解析节点
            nodes = self.parse_nodes(node_file)
            if not nodes:
                print("未找到有效节点")
                return False
            
            print(f"找到 {len(nodes)} 个节点")
            
            # 获取起始端口
            start_port = self.settings.get('start_port', 30001)
            
            # 处理每个节点
            for i, node_url in enumerate(nodes):
                # 生成端口号
                port = start_port + i
                
                # 生成入站标签
                tag = f"in_{i}"
                
                # 创建入站配置
                inbound = self.create_inbound(tag, port)
                self.singbox_config["inbounds"].append(inbound)
                
                # 转换节点为出站配置
                # 获取协议类型用于显示
                protocol_type = node_url.split('://')[0] if '://' in node_url else 'unknown'
                print(f"正在处理节点 {i+1}: {protocol_type}协议")
                outbound = self.convert_node(node_url)
                if outbound:
                    print(f"  ✅ 节点解析成功: {outbound.get('type', 'unknown')}")
                else:
                    print(f"  ❌ 节点解析失败，跳过此节点")
                    continue

                if outbound:
                    # 设置出站标签
                    outbound["tag"] = f"proxy_{i}"

                    # 清理空字段
                    outbound = self._clean_empty_fields(outbound)

                    self.singbox_config["outbounds"].append(outbound)
                    
                    # 添加路由规则
                    self.singbox_config["route"]["rules"].append({
                        "inbound": [tag],
                        "outbound": outbound["tag"]
                    })
                    
                    print(f"节点 {i+1} 配置成功，入站端口: {port}")
            
            # 添加默认出站
            self.singbox_config["outbounds"].append({
                "type": "direct",
                "tag": "direct"
            })
            
            # 写入配置文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.singbox_config, f, indent=2, ensure_ascii=False)
            
            print(f"配置文件已生成: {output_file}")
            return True
        
        except Exception as e:
            print(f"生成配置文件失败: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='将v2ray节点转换为sing-box配置')
    parser.add_argument('-i', '--input', default='node.txt', help='输入节点文件路径')
    parser.add_argument('-o', '--output', default='config.json', help='输出配置文件路径')
    parser.add_argument('-c', '--config', default='settings.json', help='设置文件路径')
    parser.add_argument('--compat-mode', action='store_true',
                       help='兼容模式：为VLESS WebSocket添加early_data支持（适用于Xray服务器）')

    args = parser.parse_args()

    # 创建转换器并生成配置
    converter = V2raySingboxConverter(args.config)

    # 如果是兼容模式，修改VLESS解析器
    if args.compat_mode:
        print("🔧 使用兼容模式生成配置（为VLESS WebSocket添加early_data支持）...")
        # 为所有VLESS WebSocket添加early_data支持
        original_vless_transport = VlessParser._build_transport

        def enhanced_vless_transport(self, transport_type: str, params_dict: Dict[str, str]) -> Optional[Dict[str, Any]]:
            transport = original_vless_transport(self, transport_type, params_dict)
            if transport and transport.get("type") == "ws":
                # 兼容模式：为VLESS WebSocket强制添加early_data支持
                transport["max_early_data"] = 2048
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                print(f"  ✅ 为VLESS WebSocket添加了early_data支持")
            return transport

        VlessParser._build_transport = enhanced_vless_transport

    success = converter.generate_config(args.input, args.output)
    
    if success:
        print(f"✅ 配置生成成功：{args.output}")
        if not args.compat_mode:
            print("\n💡 如果遇到VLESS节点403错误，请尝试兼容模式：")
            print(f"   python v2ray2singbox.py -i {args.input} -o config_compat.json --compat-mode")
        else:
            print("🔧 已使用兼容模式，VLESS WebSocket配置已优化为Xray服务器兼容")
    else:
        print("❌ 配置生成失败，请检查节点文件和设置")
    
    return success


if __name__ == '__main__':
    import sys
    main()#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import base64
import urllib.parse
import uuid
import argparse
from typing import Dict, List, Any, Optional, Tuple
from abc import ABC, abstractmethod


class ProtocolParser(ABC):
    """协议解析器基类"""

    @abstractmethod
    def can_parse(self, url: str) -> bool:
        """检查是否能解析此URL"""
        pass

    @abstractmethod
    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析URL并返回sing-box出站配置"""
        pass


class ShadowsocksParser(ProtocolParser):
    """Shadowsocks协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('ss://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析ss链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[5:]  # 移除 ss://

            # 处理有无@符号的情况
            if '@' in url_content:
                # 格式: ss://BASE64(method:password)@server:port#remarks
                auth_str, server_port = url_content.split('@', 1)

                # 处理可能的base64编码
                try:
                    decoded_auth = base64.b64decode(auth_str).decode('utf-8')
                    method, password = decoded_auth.split(':', 1)
                except:
                    # 可能已经是明文
                    method, password = auth_str.split(':', 1)

                # 处理服务器和端口
                if '#' in server_port:
                    server_port, _ = server_port.split('#', 1)

                server, port = server_port.rsplit(':', 1)
            else:
                # 格式: ss://BASE64(method:password@server:port)#remarks
                if '#' in url_content:
                    url_content, _ = url_content.split('#', 1)

                # 解码
                try:
                    decoded = base64.b64decode(url_content).decode('utf-8')
                except:
                    # 尝试添加填充
                    padding = 4 - len(url_content) % 4
                    if padding < 4:
                        url_content += '=' * padding
                    decoded = base64.b64decode(url_content).decode('utf-8')

                # 解析格式 method:password@server:port
                auth, server_port = decoded.split('@', 1)
                method, password = auth.split(':', 1)
                server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "shadowsocks",
                "server": server,
                "server_port": int(port),
                "method": method,
                "password": password
            }

            # 处理2022-blake3-aes-256-gcm特殊情况
            if method == '2022-blake3-aes-256-gcm':
                outbound = self._handle_2022_blake3(outbound, password)

            # 处理插件
            if ';' in server:
                outbound = self._handle_plugins(outbound, server)

            return outbound

        except Exception as e:
            print(f"解析ss链接失败: {e}")
            return None

    def _handle_2022_blake3(self, outbound: Dict[str, Any], password: str) -> Dict[str, Any]:
        """处理2022-blake3-aes-256-gcm加密方式"""
        if ':' in password and password.endswith('='):
            try:
                key_b64, salt_b64 = password.split(':', 1)
                key = base64.b64decode(key_b64).decode('utf-8')
                salt = base64.b64decode(salt_b64).decode('utf-8')
                outbound["password"] = f"{key}:{salt}"
            except Exception:
                pass
        elif ':' not in password:
            try:
                decoded = base64.b64decode(password).decode('utf-8')
                if ':' in decoded:
                    parts = decoded.split(':', 2)
                    if len(parts) >= 3:
                        _, key_b64, salt_b64 = parts
                        try:
                            key = base64.b64decode(key_b64).decode('utf-8')
                            salt = base64.b64decode(salt_b64).decode('utf-8')
                            outbound["password"] = f"{key}:{salt}"
                        except Exception:
                            outbound["password"] = f"{key_b64}:{salt_b64}"
                    elif len(parts) == 2:
                        key, salt = parts
                        outbound["password"] = f"{key}:{salt}"
                else:
                    # 生成随机密码作为fallback
                    import secrets
                    random_key = secrets.token_hex(16)
                    random_uuid = str(uuid.uuid4())
                    outbound["password"] = f"{random_key}:{random_uuid}"
            except Exception:
                # 生成随机密码作为fallback
                import secrets
                random_key = secrets.token_hex(16)
                random_uuid = str(uuid.uuid4())
                outbound["password"] = f"{random_key}:{random_uuid}"

        return outbound

    def _handle_plugins(self, outbound: Dict[str, Any], server: str) -> Dict[str, Any]:
        """处理SS插件"""
        server_parts = server.split(';')
        outbound["server"] = server_parts[0]

        plugin_parts = server_parts[1:]
        plugin_str = ';'.join(plugin_parts)

        if 'plugin=' in plugin_str:
            plugin_params = dict(item.split('=') for item in plugin_str.split(';') if '=' in item)
            plugin = plugin_params.get('plugin', '')

            if plugin == 'obfs-local':
                outbound["plugin"] = "obfs"
                outbound["plugin_opts"] = {
                    "mode": plugin_params.get('obfs', 'http'),
                    "host": plugin_params.get('obfs-host', '')
                }
            elif plugin == 'v2ray-plugin':
                v2ray_opts = plugin_params.get('plugin-opts', '')
                if v2ray_opts:
                    opts_dict = dict(item.split('=') for item in v2ray_opts.split(';') if '=' in item)
                    outbound["plugin"] = "v2ray-plugin"
                    outbound["plugin_opts"] = {
                        "mode": opts_dict.get('mode', 'websocket'),
                        "tls": opts_dict.get('tls', 'false') == 'true',
                        "host": opts_dict.get('host', ''),
                        "path": opts_dict.get('path', '/')
                    }

        return outbound


class VmessParser(ProtocolParser):
    """VMess协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('vmess://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析vmess链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            b64_content = url[8:]  # 移除 vmess://

            # 处理base64填充
            padding = 4 - len(b64_content) % 4
            if padding < 4:
                b64_content += '=' * padding

            try:
                decoded = base64.b64decode(b64_content).decode('utf-8')
                vmess_info = json.loads(decoded)
            except:
                decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                vmess_info = json.loads(decoded)

            outbound = {
                "type": "vmess",
                "server": vmess_info.get('add', ''),
                "server_port": int(vmess_info.get('port', 0)),
                "uuid": vmess_info.get('id', ''),
                "security": vmess_info.get('scy', 'auto'),
                "alter_id": int(vmess_info.get('aid', 0)),
                "packet_encoding": "packetaddr"  # VMess使用packetaddr
            }

            # 处理传输协议
            transport_type = vmess_info.get('net', '')
            if transport_type:
                transport = self._build_transport(transport_type, vmess_info)
                if transport:
                    outbound["transport"] = transport

            # 处理TLS
            if vmess_info.get('tls') == 'tls':
                tls = {
                    "enabled": True,
                    "server_name": vmess_info.get('sni', vmess_info.get('host', ''))
                }

                if vmess_info.get('verify_cert_chain', True) is False or vmess_info.get('allowInsecure', False):
                    tls["insecure"] = True

                outbound["tls"] = tls

            return outbound

        except Exception as e:
            print(f"解析vmess链接失败: {e}")
            return None

    def _build_transport(self, transport_type: str, vmess_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            transport = {
                "type": "ws",
                "path": vmess_info.get('path', '/')
            }
            if 'host' in vmess_info and vmess_info.get('host'):
                transport["headers"] = {"Host": vmess_info['host']}

            # VMess WebSocket需要early_data配置（根据v2ray-agent脚本）
            transport["max_early_data"] = 2048
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"

            return transport

        elif transport_type == 'tcp':
            transport = {"type": "tcp"}
            if vmess_info.get('type') == 'http':
                transport["header"] = {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [vmess_info.get('path', '/')]
                    }
                }
                if 'host' in vmess_info and vmess_info.get('host'):
                    transport["header"]["request"]["headers"] = {"Host": [vmess_info['host']]}
            return transport

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": vmess_info.get('path', ''),
                "multi_mode": False
            }

        elif transport_type == 'quic':
            return {"type": "quic"}

        elif transport_type == 'h2':
            return {
                "type": "http",
                "host": [vmess_info.get('host', '')],
                "path": vmess_info.get('path', '/')
            }

        return None


class TrojanParser(ProtocolParser):
    """Trojan协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('trojan://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析trojan链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[9:]  # 移除 trojan://

            if '@' not in url_content:
                return None

            password, server_info = url_content.split('@', 1)

            # 处理查询参数和备注
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_dict = dict(item.split('=') for item in params.split('&') if '=' in item)
            else:
                if '#' in server_info:
                    server_port, _ = server_info.split('#', 1)
                else:
                    server_port = server_info

            # 解析服务器和端口
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": params_dict.get('sni', params_dict.get('host', server)),
                    "insecure": False
                }
            }

            # 处理TLS安全选项
            if params_dict.get('allowInsecure', '0') == '1' or params_dict.get('insecure', '0') == '1':
                outbound["tls"]["insecure"] = True

            # 处理传输协议
            transport_type = params_dict.get('type', '')
            if transport_type:
                transport = self._build_transport(transport_type, params_dict)
                if transport:
                    outbound["transport"] = transport

            return outbound

        except Exception as e:
            print(f"解析trojan链接失败: {e}")
            return None

    def _build_transport(self, transport_type: str, params_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            ws = {"type": "ws", "path": params_dict.get('path', '/')}
            if 'host' in params_dict and params_dict.get('host'):
                ws["headers"] = {"Host": params_dict['host']}
            return ws

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": params_dict.get('serviceName', ''),
                "multi_mode": False
            }

        return None


class VlessParser(ProtocolParser):
    """VLESS协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('vless://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析vless链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[8:]  # 移除 vless://

            if '@' not in url_content:
                return None

            uuid_str, server_info = url_content.split('@', 1)

            # 处理备注信息
            if '#' in server_info:
                server_info, remark = server_info.split('#', 1)
                remark = urllib.parse.unquote(remark)

            # 处理查询参数
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_list = params.split('&')
                for item in params_list:
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params_dict[k] = urllib.parse.unquote(v)
            else:
                server_port = server_info

            # 解析服务器和端口
            if ':' not in server_port:
                return None

            server, port = server_port.rsplit(':', 1)

            # 创建基础出站配置
            outbound = {
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": uuid_str
            }

            # 处理flow字段 - 只有非空值才添加
            flow = params_dict.get('flow', '')
            if flow and flow.strip():
                outbound["flow"] = flow

            # 处理安全类型
            security = params_dict.get('security', 'none')
            if security == 'tls':
                outbound["tls"] = self._build_tls_config(params_dict, server)

            # 处理传输协议
            transport_type = params_dict.get('type', '')
            if transport_type:
                transport = self._build_transport(transport_type, params_dict)
                if transport:
                    outbound["transport"] = transport

                    # 根据协议类型设置正确的packet_encoding
                    # VLESS使用xudp编码
                    outbound["packet_encoding"] = "xudp"

            return outbound

        except Exception as e:
            print(f"解析vless链接失败: {e}")
            return None

    def _build_tls_config(self, params_dict: Dict[str, Any], server: str) -> Dict[str, Any]:
        """构建TLS配置"""
        tls = {
            "enabled": True,
            "server_name": params_dict.get('sni', params_dict.get('host', server)),
            "insecure": False
        }

        # 处理跳过证书验证
        if params_dict.get('allowInsecure', '0') == '1' or params_dict.get('insecure', '0') == '1':
            tls["insecure"] = True

        # 处理指纹
        if 'fp' in params_dict and params_dict.get('fp'):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": params_dict.get('fp', 'chrome')
            }

        return tls

    def _build_transport(self, transport_type: str, params_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输配置"""
        if transport_type == 'ws':
            # WebSocket配置 - 智能兼容V2Ray和Xray服务器
            transport = {
                "type": "ws",
                "path": params_dict.get('path', '/')
            }

            # 设置Host头
            if 'host' in params_dict and params_dict.get('host'):
                transport["headers"] = {
                    "Host": params_dict['host']
                }

            # 智能early_data配置：
            # 1. 如果URL中有ed参数，说明服务器支持early_data，按Xray模式配置
            # 2. 如果没有ed参数，使用sing-box默认模式（通过path发送）
            if 'ed' in params_dict:
                # Xray兼容模式
                try:
                    transport["max_early_data"] = int(params_dict['ed'])
                except ValueError:
                    transport["max_early_data"] = 2048
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"

            return transport

        elif transport_type == 'grpc':
            return {
                "type": "grpc",
                "service_name": params_dict.get('serviceName', params_dict.get('path', '')),
                "multi_mode": False
            }

        elif transport_type == 'tcp':
            return {"type": "tcp"}

        elif transport_type == 'http':
            return {
                "type": "http",
                "host": [params_dict.get('host', '')],
                "path": params_dict.get('path', '/')
            }

        return None


class Hysteria2Parser(ProtocolParser):
    """Hysteria2协议解析器"""

    def can_parse(self, url: str) -> bool:
        return url.startswith('hysteria2://')

    def parse(self, url: str) -> Optional[Dict[str, Any]]:
        """解析hysteria2链接并转换为sing-box出站配置"""
        try:
            if not self.can_parse(url):
                return None

            url_content = url[12:]  # 移除 hysteria2://

            if '@' not in url_content:
                return None

            auth, server_info = url_content.split('@', 1)

            # 处理备注信息
            if '#' in server_info:
                server_info, remark = server_info.split('#', 1)

            # 处理查询参数
            params_dict = {}
            if '?' in server_info:
                server_port, params = server_info.split('?', 1)
                params_list = params.split('&')
                for item in params_list:
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params_dict[k] = urllib.parse.unquote(v)
            else:
                server_port = server_info

            # 解析服务器和端口
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "hysteria2",
                "server": server,
                "server_port": int(port),
                "password": auth,
                "tls": {
                    "enabled": True,
                    "server_name": params_dict.get('sni', server),
                    "insecure": False
                }
            }

            # 处理TLS安全选项
            if params_dict.get('insecure', '0') == '1':
                outbound["tls"]["insecure"] = True

            # 处理其他参数
            if 'obfs' in params_dict:
                outbound["obfs"] = params_dict['obfs']

            if 'obfs-password' in params_dict:
                outbound["obfs_password"] = params_dict['obfs-password']

            # 添加带宽控制
            if 'up' in params_dict:
                try:
                    outbound["up_mbps"] = int(params_dict['up'])
                except ValueError:
                    pass

            if 'down' in params_dict:
                try:
                    outbound["down_mbps"] = int(params_dict['down'])
                except ValueError:
                    pass

            return outbound

        except Exception as e:
            print(f"解析hysteria2链接失败: {e}")
            return None


class V2raySingboxConverter:
    def __init__(self, config_file: str = 'settings.json'):
        # 默认配置
        self.default_settings = {
            'username': 'root',
            'password': 'root',
            'start_port': 30001,
            'listen': '127.0.0.1'
        }

        # 尝试加载配置文件
        self.settings = self.load_settings(config_file)

        # 初始化协议解析器
        self.parsers = [
            ShadowsocksParser(),
            VmessParser(),
            TrojanParser(),
            VlessParser(),
            Hysteria2Parser()
        ]

        # 初始化sing-box配置模板
        self.singbox_config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "inbounds": [],
            "outbounds": [],
            "route": {
                "rules": [],
                "final": "direct"
            }
        }
    
    def load_settings(self, config_file: str) -> Dict[str, Any]:
        """加载设置文件，如果不存在则创建默认设置"""
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}，使用默认配置")
                return self.default_settings
        else:
            # 创建默认配置文件
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.default_settings, f, indent=4, ensure_ascii=False)
            print(f"已创建默认配置文件: {config_file}")
            return self.default_settings
    
    def parse_nodes(self, node_file: str) -> List[str]:
        """解析节点文件，提取有效节点"""
        nodes = []
        
        try:
            with open(node_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                # 跳过空行和不包含://的行（通常是分类标题）
                if line and '://' in line:
                    nodes.append(line)
        except Exception as e:
            print(f"解析节点文件失败: {e}")
        
        return nodes

    def _clean_empty_fields(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """清理配置中的空字段"""
        cleaned = {}
        for key, value in config.items():
            # 跳过空值、空字符串、空字典和空列表
            if value is not None and value != '' and value != {} and value != []:
                if isinstance(value, dict):
                    cleaned_dict = self._clean_empty_fields(value)
                    if cleaned_dict:
                        cleaned[key] = cleaned_dict
                elif isinstance(value, str) and value.strip():
                    # 只保留非空字符串
                    cleaned[key] = value
                elif not isinstance(value, str):
                    # 保留非字符串类型的值
                    cleaned[key] = value
        return cleaned

    def create_inbound(self, tag: str, port: int) -> Dict[str, Any]:
        """创建入站配置"""
        listen = self.settings.get('listen', '::')
        # 如果监听地址为空，则使用::允许所有连接
        if not listen:
            listen = '::'
            
        return {
            "type": "mixed",
            "tag": tag,
            "listen": listen,
            "listen_port": port,
            "users": [
                {
                    "username": self.settings.get('username', 'root'),
                    "password": self.settings.get('password', 'root')
                }
            ]
        }
    
    def convert_node(self, node_url: str) -> Optional[Dict[str, Any]]:
        """根据节点URL类型调用相应的解析函数"""
        for parser in self.parsers:
            if parser.can_parse(node_url):
                print(f"    🔍 使用 {parser.__class__.__name__} 解析")
                result = parser.parse(node_url)
                if result:
                    print(f"    ✅ 解析成功")
                else:
                    print(f"    ❌ 解析失败")
                return result

        protocol_type = node_url.split('://')[0] if '://' in node_url else 'unknown'
        print(f"    ❌ 不支持的节点类型: {protocol_type}")
        return None



    def generate_config(self, node_file: str, output_file: str = 'config.json') -> bool:
        """生成sing-box配置文件"""
        try:
            # 解析节点
            nodes = self.parse_nodes(node_file)
            if not nodes:
                print("未找到有效节点")
                return False
            
            print(f"找到 {len(nodes)} 个节点")
            
            # 获取起始端口
            start_port = self.settings.get('start_port', 30001)
            
            # 处理每个节点
            for i, node_url in enumerate(nodes):
                # 生成端口号
                port = start_port + i
                
                # 生成入站标签
                tag = f"in_{i}"
                
                # 创建入站配置
                inbound = self.create_inbound(tag, port)
                self.singbox_config["inbounds"].append(inbound)
                
                # 转换节点为出站配置
                # 获取协议类型用于显示
                protocol_type = node_url.split('://')[0] if '://' in node_url else 'unknown'
                print(f"正在处理节点 {i+1}: {protocol_type}协议")
                outbound = self.convert_node(node_url)
                if outbound:
                    print(f"  ✅ 节点解析成功: {outbound.get('type', 'unknown')}")
                else:
                    print(f"  ❌ 节点解析失败，跳过此节点")
                    continue

                if outbound:
                    # 设置出站标签
                    outbound["tag"] = f"proxy_{i}"

                    # 清理空字段
                    outbound = self._clean_empty_fields(outbound)

                    self.singbox_config["outbounds"].append(outbound)
                    
                    # 添加路由规则
                    self.singbox_config["route"]["rules"].append({
                        "inbound": [tag],
                        "outbound": outbound["tag"]
                    })
                    
                    print(f"节点 {i+1} 配置成功，入站端口: {port}")
            
            # 添加默认出站
            self.singbox_config["outbounds"].append({
                "type": "direct",
                "tag": "direct"
            })
            
            # 写入配置文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.singbox_config, f, indent=2, ensure_ascii=False)
            
            print(f"配置文件已生成: {output_file}")
            return True
        
        except Exception as e:
            print(f"生成配置文件失败: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='将v2ray节点转换为sing-box配置')
    parser.add_argument('-i', '--input', default='node.txt', help='输入节点文件路径')
    parser.add_argument('-o', '--output', default='config.json', help='输出配置文件路径')
    parser.add_argument('-c', '--config', default='settings.json', help='设置文件路径')
    parser.add_argument('--compat-mode', action='store_true',
                       help='兼容模式：为VLESS WebSocket添加early_data支持（适用于Xray服务器）')

    args = parser.parse_args()

    # 创建转换器并生成配置
    converter = V2raySingboxConverter(args.config)

    # 如果是兼容模式，修改VLESS解析器
    if args.compat_mode:
        print("🔧 使用兼容模式生成配置（为VLESS WebSocket添加early_data支持）...")
        # 为所有VLESS WebSocket添加early_data支持
        original_vless_transport = VlessParser._build_transport

        def enhanced_vless_transport(self, transport_type: str, params_dict: Dict[str, str]) -> Optional[Dict[str, Any]]:
            transport = original_vless_transport(self, transport_type, params_dict)
            if transport and transport.get("type") == "ws":
                # 兼容模式：为VLESS WebSocket强制添加early_data支持
                transport["max_early_data"] = 2048
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                print(f"  ✅ 为VLESS WebSocket添加了early_data支持")
            return transport

        VlessParser._build_transport = enhanced_vless_transport

    success = converter.generate_config(args.input, args.output)
    
    if success:
        print(f"✅ 配置生成成功：{args.output}")
        if not args.compat_mode:
            print("\n💡 如果遇到VLESS节点403错误，请尝试兼容模式：")
            print(f"   python v2ray2singbox.py -i {args.input} -o config_compat.json --compat-mode")
        else:
            print("🔧 已使用兼容模式，VLESS WebSocket配置已优化为Xray服务器兼容")
    else:
        print("❌ 配置生成失败，请检查节点文件和设置")
    
    return success


if __name__ == '__main__':
    import sys
    main()
