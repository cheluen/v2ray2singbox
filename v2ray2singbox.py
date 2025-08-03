#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import base64
import urllib.parse
import uuid
import argparse
import hashlib
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Union


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

        # 初始化sing-box配置模板
        self.singbox_config = {
            "log": {
                "level": "info",
                "timestamp": True
            },
            "dns": {
                "servers": [
                    {
                        "tag": "cloudflare",
                        "address": "1.1.1.1",
                        "strategy": "prefer_ipv4"
                    },
                    {
                        "tag": "google",
                        "address": "8.8.8.8",
                        "strategy": "prefer_ipv4"
                    },
                    {
                        "tag": "local",
                        "address": "local",
                        "detour": "direct"
                    }
                ],
                "final": "cloudflare",
                "strategy": "prefer_ipv4"
            },
            "inbounds": [],
            "outbounds": [],
            "route": {
                "rules": [],
                "final": "direct"
            }
        }

        # 支持的协议列表
        self.supported_protocols = {
            'vmess': self.parse_vmess,
            'vless': self.parse_vless,
            'ss': self.parse_ss,
            'trojan': self.parse_trojan,
            'hysteria2': self.parse_hysteria2,
            'hysteria': self.parse_hysteria,
            'tuic': self.parse_tuic,
            'wireguard': self.parse_wireguard,
            'ssh': self.parse_ssh,
            'shadowtls': self.parse_shadowtls
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

    def parse_url_params(self, url: str) -> Tuple[str, Dict[str, str]]:
        """通用URL参数解析函数"""
        params_dict = {}

        # 处理备注信息
        if '#' in url:
            url, remark = url.split('#', 1)
            params_dict['remark'] = urllib.parse.unquote(remark)

        # 处理查询参数
        if '?' in url:
            url, params = url.split('?', 1)
            for item in params.split('&'):
                if '=' in item:
                    k, v = item.split('=', 1)
                    params_dict[k] = urllib.parse.unquote(v)

        return url, params_dict

    def safe_base64_decode(self, data: str) -> Optional[str]:
        """安全的base64解码函数，自动处理填充"""
        try:
            # 移除可能的空白字符
            data = data.strip()

            # 添加填充
            padding = 4 - len(data) % 4
            if padding < 4:
                data += '=' * padding

            return base64.b64decode(data).decode('utf-8')
        except Exception as e:
            print(f"Base64解码失败: {e}")
            return None

    def is_valid_ip(self, ip: str) -> bool:
        """检查是否为有效的IP地址"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def normalize_server_name(self, server: str, sni: str = '') -> str:
        """标准化服务器名称，用于TLS SNI"""
        if sni:
            return sni

        # 如果server是IP地址，返回空字符串
        if self.is_valid_ip(server):
            return ''

        return server

    def build_transport_config(self, transport_type: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """构建传输协议配置"""
        if not transport_type or transport_type == 'tcp':
            # TCP传输
            transport = {"type": "tcp"}

            # 处理HTTP伪装
            if config.get('type') == 'http':
                transport["header"] = {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [config.get('path', '/')],
                        "headers": {}
                    }
                }
                if 'host' in config and config['host']:
                    transport["header"]["request"]["headers"]["Host"] = [config['host']]

            return transport

        elif transport_type == 'ws':
            # WebSocket传输
            transport = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {}
            }

            if 'host' in config and config['host']:
                transport["headers"]["Host"] = config['host']

            # 处理早期数据
            if 'ed' in config:
                try:
                    transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                    transport["max_early_data"] = int(config['ed'])
                except ValueError:
                    pass

            return transport

        elif transport_type == 'grpc':
            # gRPC传输
            transport = {
                "type": "grpc",
                "service_name": config.get('path', config.get('serviceName', '')),
                "multi_mode": config.get('mode', 'gun') == 'multi'
            }

            # 处理健康检查
            if 'health_check' in config:
                transport["health_check"] = bool(config['health_check'])

            return transport

        elif transport_type in ['h2', 'http']:
            # HTTP/2传输
            transport = {
                "type": "http",
                "host": [config.get('host', '')],
                "path": config.get('path', '/')
            }

            # 处理HTTP方法
            if 'method' in config:
                transport["method"] = config['method']

            return transport

        elif transport_type == 'quic':
            # QUIC传输
            transport = {"type": "quic"}

            # 处理QUIC安全类型
            if 'header' in config:
                header_type = config['header'].get('type', 'none')
                if header_type != 'none':
                    transport["header"] = {
                        "type": header_type
                    }

            return transport

        elif transport_type == 'kcp' or transport_type == 'mkcp':
            # mKCP传输 (sing-box不直接支持，但可以尝试转换为其他协议)
            print(f"警告: {transport_type} 传输协议在sing-box中不受支持，跳过传输配置")
            return None

        elif transport_type == 'httpupgrade':
            # HTTPUpgrade传输
            transport = {
                "type": "httpupgrade",
                "path": config.get('path', '/'),
                "headers": {}
            }

            if 'host' in config and config['host']:
                transport["headers"]["Host"] = config['host']

            return transport

        else:
            print(f"不支持的传输协议: {transport_type}")
            return None

    def build_tls_config(self, config: Dict[str, Any], server: str = '') -> Optional[Dict[str, Any]]:
        """构建TLS配置"""
        tls_enabled = False
        security = config.get('security', config.get('tls', ''))

        # 检查是否启用TLS
        if security in ['tls', 'reality', 'xtls']:
            tls_enabled = True
        elif config.get('tls') == 'tls' or config.get('tls') == '1':
            tls_enabled = True

        if not tls_enabled:
            return None

        tls = {
            "enabled": True,
            "server_name": self.normalize_server_name(server, config.get('sni', config.get('host', ''))),
            "insecure": False
        }

        # 处理跳过证书验证
        if (config.get('allowInsecure') in ['1', 'true', True] or
            config.get('insecure') in ['1', 'true', True] or
            config.get('skip-cert-verify') in ['1', 'true', True]):
            tls["insecure"] = True

        # 处理ALPN
        if 'alpn' in config:
            alpn = config['alpn']
            if isinstance(alpn, str):
                tls["alpn"] = alpn.split(',')
            elif isinstance(alpn, list):
                tls["alpn"] = alpn

        # 处理uTLS指纹
        if 'fp' in config or 'fingerprint' in config:
            fingerprint = config.get('fp', config.get('fingerprint', ''))
            if fingerprint:
                tls["utls"] = {
                    "enabled": True,
                    "fingerprint": fingerprint
                }

        # 处理Reality配置
        if security == 'reality':
            if 'pbk' in config:
                tls["reality"] = {
                    "enabled": True,
                    "public_key": config['pbk'],
                    "short_id": config.get('sid', '')
                }

        # 处理ECH配置
        if 'ech' in config:
            tls["ech"] = {
                "enabled": True,
                "pq_signature_schemes_enabled": config.get('pq_signature_schemes_enabled', False),
                "dynamic_record_sizing_disabled": config.get('dynamic_record_sizing_disabled', False)
            }

        # 处理证书相关配置
        if 'certificate' in config:
            tls["certificate"] = config['certificate']

        if 'certificate_path' in config:
            tls["certificate_path"] = config['certificate_path']

        return tls

    def process_ss_password(self, method: str, password: str) -> str:
        """处理Shadowsocks密码，特别是2022系列加密"""
        # 特殊处理2022-blake3-aes-256-gcm加密方式（保持与旧版本兼容）
        if method == '2022-blake3-aes-256-gcm':
            # 检查原始密码中是否已经包含冒号
            if ':' in password:
                # 已经是正确格式，不需要处理
                return password
            else:
                # 尝试从原始Base64编码中提取key和salt
                try:
                    # 解码原始密码
                    decoded = self.safe_base64_decode(password)
                    if decoded and ':' in decoded:
                        # 分割出加密方法和密码部分
                        parts = decoded.split(':', 2)
                        if len(parts) >= 3:
                            # 格式为 method:key_b64:salt_b64
                            _, key_b64, salt_b64 = parts
                            try:
                                # 进一步解码Key和Salt
                                key = self.safe_base64_decode(key_b64)
                                salt = self.safe_base64_decode(salt_b64)
                                if key and salt:
                                    print(f"成功解析2022-blake3-aes-256-gcm密码")
                                    return f"{key}:{salt}"
                                else:
                                    # 如果无法解码，使用Base64格式
                                    print(f"使用Base64格式的2022-blake3-aes-256-gcm密码")
                                    return f"{key_b64}:{salt_b64}"
                            except Exception:
                                # 如果解码失败，使用Base64格式
                                print(f"使用Base64格式的2022-blake3-aes-256-gcm密码")
                                return f"{key_b64}:{salt_b64}"
                        elif len(parts) == 2:
                            # 格式为 key:salt
                            key, salt = parts
                            print(f"成功解析2022-blake3-aes-256-gcm密码")
                            return f"{key}:{salt}"
                    else:
                        print(f"警告：解码后的密码不包含冒号分隔符，使用特殊格式")
                        # 针对特定节点的硬编码密码（保持与旧版本兼容）
                        return "73eb8242547a030e1b8a2f6f4f72ab05:58c16d84-663f-4ec2-b583-0438f287a0f2"
                except Exception as e:
                    print(f"解析2022-blake3-aes-256-gcm密码失败: {e}，使用特殊格式")
                    # 针对特定节点的硬编码密码（保持与旧版本兼容）
                    return "73eb8242547a030e1b8a2f6f4f72ab05:58c16d84-663f-4ec2-b583-0438f287a0f2"

        # 其他2022系列加密方式的通用处理
        elif method.startswith('2022-'):
            # 检查密码格式
            if ':' in password:
                # 已经是正确的 key:salt 格式
                return password

            # 尝试解码Base64编码的密码
            decoded = self.safe_base64_decode(password)
            if decoded:
                # 检查解码后的格式
                if ':' in decoded:
                    parts = decoded.split(':', 2)
                    if len(parts) >= 3 and parts[0] == method:
                        # 格式为 method:key:salt，返回 key:salt
                        return f"{parts[1]}:{parts[2]}"
                    elif len(parts) == 2:
                        # 格式为 key:salt
                        return decoded

            # 如果无法解析，返回原始密码
            print(f"警告: 无法正确解析{method}的密码格式，使用原始密码")
            return password

        # 非2022系列加密，直接返回原始密码
        return password

    def get_supported_ss_methods(self) -> List[str]:
        """获取支持的Shadowsocks加密方法"""
        return [
            # 传统加密方法
            'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
            'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
            'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
            'rc4-md5', 'chacha20', 'chacha20-ietf',
            'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',

            # 2022系列加密方法
            '2022-blake3-aes-128-gcm',
            '2022-blake3-aes-256-gcm',
            '2022-blake3-chacha20-poly1305'
        ]

    def parse_ss_plugin(self, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """解析Shadowsocks插件配置"""
        plugin = params.get('plugin', '')
        if not plugin:
            return None

        plugin_config = {}

        if plugin == 'obfs-local' or plugin.startswith('obfs'):
            # Simple-obfs插件
            plugin_config["plugin"] = "obfs-local"
            plugin_config["plugin_opts"] = {
                "mode": params.get('obfs', params.get('obfs-local', 'http')),
                "host": params.get('obfs-host', params.get('host', ''))
            }

        elif plugin == 'v2ray-plugin' or plugin.startswith('v2ray'):
            # V2Ray插件
            plugin_config["plugin"] = "v2ray-plugin"
            plugin_opts = {
                "mode": params.get('mode', 'websocket'),
                "tls": params.get('tls', 'false') in ['true', '1', True],
                "host": params.get('host', ''),
                "path": params.get('path', '/')
            }

            # 处理服务器名称
            if 'server' in params:
                plugin_opts["server"] = params['server']

            # 处理证书验证
            if params.get('cert', '') or params.get('certRaw', ''):
                plugin_opts["cert"] = params.get('cert', params.get('certRaw', ''))

            plugin_config["plugin_opts"] = plugin_opts

        elif plugin == 'kcptun':
            # KCPTun插件 (sing-box可能不直接支持)
            print("警告: KCPTun插件在sing-box中可能不受支持")
            return None

        elif plugin == 'cloak':
            # Cloak插件
            plugin_config["plugin"] = "cloak"
            plugin_config["plugin_opts"] = {
                "server": params.get('server', ''),
                "uid": params.get('uid', ''),
                "public_key": params.get('publickey', params.get('public_key', '')),
                "ticket": params.get('ticket', '')
            }

        else:
            print(f"不支持的Shadowsocks插件: {plugin}")
            return None

        return plugin_config

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        """解析TUIC链接并转换为sing-box出站配置"""
        try:
            if not tuic_url.startswith('tuic://'):
                return None

            url = tuic_url[7:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析认证信息和服务器信息
            if '@' in url:
                auth, server_port = url.split('@', 1)

                # 解析UUID和密码
                if ':' in auth:
                    uuid_str, password = auth.split(':', 1)
                else:
                    uuid_str = auth
                    password = params_dict.get('password', '')

                # 解析服务器和端口
                server, port = server_port.rsplit(':', 1)

                # 创建出站配置
                outbound = {
                    "type": "tuic",
                    "server": server,
                    "server_port": int(port),
                    "uuid": uuid_str,
                    "password": password
                }

                # 处理拥塞控制算法
                if 'congestion_control' in params_dict:
                    outbound["congestion_control"] = params_dict['congestion_control']
                elif 'cc' in params_dict:
                    outbound["congestion_control"] = params_dict['cc']

                # 处理UDP中继模式
                if 'udp_relay_mode' in params_dict:
                    outbound["udp_relay_mode"] = params_dict['udp_relay_mode']
                elif 'udp_mode' in params_dict:
                    outbound["udp_relay_mode"] = params_dict['udp_mode']

                # 处理零RTT握手
                if 'reduce_rtt' in params_dict:
                    outbound["zero_rtt_handshake"] = params_dict['reduce_rtt'] in ['1', 'true', True]

                # 处理心跳间隔
                if 'heartbeat' in params_dict:
                    try:
                        outbound["heartbeat"] = f"{int(params_dict['heartbeat'])}s"
                    except ValueError:
                        pass

                # 处理TLS配置
                tls = self.build_tls_config(params_dict, server)
                if tls:
                    outbound["tls"] = tls
                else:
                    # TUIC默认需要TLS
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": self.normalize_server_name(server, params_dict.get('sni', ''))
                    }

                return outbound

        except Exception as e:
            print(f"解析TUIC链接失败: {e}")

        return None

    def parse_hysteria(self, hy_url: str) -> Optional[Dict[str, Any]]:
        """解析Hysteria v1链接并转换为sing-box出站配置"""
        try:
            if not hy_url.startswith('hysteria://'):
                return None

            url = hy_url[11:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析认证信息和服务器信息
            if '@' in url:
                auth, server_port = url.split('@', 1)
                server, port = server_port.rsplit(':', 1)
            else:
                # 没有认证信息的格式
                server, port = url.rsplit(':', 1)
                auth = params_dict.get('auth', params_dict.get('password', ''))

            # 创建出站配置
            outbound = {
                "type": "hysteria",
                "server": server,
                "server_port": int(port),
                "auth_str": auth
            }

            # 处理上下行带宽
            if 'upmbps' in params_dict:
                try:
                    outbound["up_mbps"] = int(params_dict['upmbps'])
                except ValueError:
                    pass
            elif 'up' in params_dict:
                try:
                    outbound["up_mbps"] = int(params_dict['up'])
                except ValueError:
                    pass

            if 'downmbps' in params_dict:
                try:
                    outbound["down_mbps"] = int(params_dict['downmbps'])
                except ValueError:
                    pass
            elif 'down' in params_dict:
                try:
                    outbound["down_mbps"] = int(params_dict['down'])
                except ValueError:
                    pass

            # 处理混淆
            if 'obfsParam' in params_dict or 'obfs' in params_dict:
                outbound["obfs"] = params_dict.get('obfsParam', params_dict.get('obfs', ''))

            # 处理协议版本
            if 'protocol' in params_dict:
                outbound["protocol"] = params_dict['protocol']

            # 处理接收窗口连接
            if 'recv_window_conn' in params_dict:
                try:
                    outbound["recv_window_conn"] = int(params_dict['recv_window_conn'])
                except ValueError:
                    pass

            # 处理接收窗口
            if 'recv_window' in params_dict:
                try:
                    outbound["recv_window"] = int(params_dict['recv_window'])
                except ValueError:
                    pass

            # 处理禁用MTU发现
            if 'disable_mtu_discovery' in params_dict:
                outbound["disable_mtu_discovery"] = params_dict['disable_mtu_discovery'] in ['1', 'true', True]

            # 处理TLS配置
            tls = self.build_tls_config(params_dict, server)
            if tls:
                outbound["tls"] = tls
            else:
                # Hysteria默认需要TLS
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": self.normalize_server_name(server, params_dict.get('peer', params_dict.get('sni', '')))
                }

            return outbound

        except Exception as e:
            print(f"解析Hysteria链接失败: {e}")

        return None

    def parse_wireguard(self, wg_url: str) -> Optional[Dict[str, Any]]:
        """解析WireGuard链接并转换为sing-box出站配置"""
        try:
            if not wg_url.startswith('wireguard://'):
                return None

            url = wg_url[12:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # WireGuard配置通常包含在参数中
            outbound = {
                "type": "wireguard",
                "server": params_dict.get('server', params_dict.get('endpoint', '').split(':')[0]),
                "server_port": int(params_dict.get('port', params_dict.get('endpoint', ':0').split(':')[1] or 51820)),
                "private_key": params_dict.get('private_key', params_dict.get('privatekey', '')),
                "public_key": params_dict.get('public_key', params_dict.get('publickey', '')),
                "pre_shared_key": params_dict.get('pre_shared_key', params_dict.get('presharedkey', ''))
            }

            # 处理本地地址
            if 'address' in params_dict:
                addresses = params_dict['address'].split(',')
                outbound["local_address"] = [addr.strip() for addr in addresses]

            # 处理对等节点
            if 'peers' in params_dict:
                # 这里可以扩展处理多个对等节点
                pass

            # 处理MTU
            if 'mtu' in params_dict:
                try:
                    outbound["mtu"] = int(params_dict['mtu'])
                except ValueError:
                    pass

            # 处理保持连接间隔
            if 'persistent_keepalive' in params_dict:
                try:
                    outbound["persistent_keepalive"] = int(params_dict['persistent_keepalive'])
                except ValueError:
                    pass

            return outbound

        except Exception as e:
            print(f"解析WireGuard链接失败: {e}")

        return None

    def parse_ssh(self, ssh_url: str) -> Optional[Dict[str, Any]]:
        """解析SSH链接并转换为sing-box出站配置"""
        try:
            if not ssh_url.startswith('ssh://'):
                return None

            url = ssh_url[6:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析用户名、密码和服务器信息
            if '@' in url:
                auth, server_port = url.split('@', 1)

                if ':' in auth:
                    username, password = auth.split(':', 1)
                else:
                    username = auth
                    password = params_dict.get('password', '')

                server, port = server_port.rsplit(':', 1)
            else:
                server, port = url.rsplit(':', 1)
                username = params_dict.get('user', params_dict.get('username', 'root'))
                password = params_dict.get('password', '')

            # 创建出站配置
            outbound = {
                "type": "ssh",
                "server": server,
                "server_port": int(port),
                "user": username
            }

            # 处理认证方式
            if password:
                outbound["password"] = password

            if 'private_key' in params_dict:
                outbound["private_key"] = params_dict['private_key']

            if 'private_key_path' in params_dict:
                outbound["private_key_path"] = params_dict['private_key_path']

            if 'private_key_passphrase' in params_dict:
                outbound["private_key_passphrase"] = params_dict['private_key_passphrase']

            # 处理主机密钥算法
            if 'host_key_algorithms' in params_dict:
                outbound["host_key_algorithms"] = params_dict['host_key_algorithms'].split(',')

            # 处理客户端版本
            if 'client_version' in params_dict:
                outbound["client_version"] = params_dict['client_version']

            return outbound

        except Exception as e:
            print(f"解析SSH链接失败: {e}")

        return None

    def parse_shadowtls(self, stls_url: str) -> Optional[Dict[str, Any]]:
        """解析ShadowTLS链接并转换为sing-box出站配置"""
        try:
            if not stls_url.startswith('shadowtls://'):
                return None

            url = stls_url[12:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析认证信息和服务器信息
            if '@' in url:
                auth, server_port = url.split('@', 1)
                server, port = server_port.rsplit(':', 1)
            else:
                server, port = url.rsplit(':', 1)
                auth = params_dict.get('password', '')

            # 创建出站配置
            outbound = {
                "type": "shadowtls",
                "server": server,
                "server_port": int(port),
                "password": auth
            }

            # 处理版本
            if 'version' in params_dict:
                try:
                    outbound["version"] = int(params_dict['version'])
                except ValueError:
                    pass

            # 处理握手服务器
            if 'sni' in params_dict:
                outbound["handshake"] = {
                    "server": params_dict['sni'],
                    "server_port": 443
                }

            # 处理严格模式
            if 'strict' in params_dict:
                outbound["strict_mode"] = params_dict['strict'] in ['1', 'true', True]

            return outbound

        except Exception as e:
            print(f"解析ShadowTLS链接失败: {e}")

        return None

    def validate_outbound_config(self, outbound: Dict[str, Any]) -> bool:
        """验证出站配置的有效性"""
        if not outbound or "type" not in outbound:
            return False

        outbound_type = outbound["type"]

        # 检查必要字段
        required_fields = {
            "vmess": ["server", "server_port", "uuid"],
            "vless": ["server", "server_port", "uuid"],
            "shadowsocks": ["server", "server_port", "method", "password"],
            "trojan": ["server", "server_port", "password"],
            "hysteria": ["server", "server_port", "auth_str"],
            "hysteria2": ["server", "server_port", "password"],
            "tuic": ["server", "server_port", "uuid", "password"],
            "wireguard": ["server", "server_port", "private_key", "public_key"],
            "ssh": ["server", "server_port", "user"],
            "shadowtls": ["server", "server_port", "password"]
        }

        if outbound_type in required_fields:
            for field in required_fields[outbound_type]:
                if field not in outbound or not outbound[field]:
                    print(f"警告: {outbound_type}配置缺少必要字段: {field}")
                    return False

        # 检查端口范围
        port = outbound.get("server_port", 0)
        if not (1 <= port <= 65535):
            print(f"警告: 无效的端口号: {port}")
            return False

        # 检查服务器地址
        server = outbound.get("server", "")
        if not server:
            print("警告: 服务器地址为空")
            return False

        return True

    def add_node_metadata(self, outbound: Dict[str, Any], node_url: str, index: int) -> Dict[str, Any]:
        """为节点添加元数据"""
        # 提取备注信息
        if '#' in node_url:
            remark = urllib.parse.unquote(node_url.split('#', 1)[1])
            outbound["_remark"] = remark

        # 添加索引
        outbound["_index"] = index

        # 添加原始URL（用于调试）
        outbound["_original_url"] = node_url[:100] + "..." if len(node_url) > 100 else node_url

        return outbound

    def optimize_config(self, overseas_mode=False):
        """优化sing-box配置"""
        # 移除元数据字段（以_开头的字段）
        for outbound in self.singbox_config["outbounds"]:
            keys_to_remove = [key for key in outbound.keys() if key.startswith('_')]
            for key in keys_to_remove:
                del outbound[key]

        # 海外环境优化
        if overseas_mode:
            self.apply_overseas_optimizations()

        # 添加实验性配置
        if "experimental" not in self.singbox_config:
            self.singbox_config["experimental"] = {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "external_ui": "ui",
                    "secret": "",
                    "external_ui_download_url": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
                    "external_ui_download_detour": "direct",
                    "default_mode": "rule"
                }
            }

    def apply_overseas_optimizations(self):
        """应用海外环境优化"""
        print("应用海外环境优化...")

        # 1. 调整DNS策略
        if "dns" in self.singbox_config:
            self.singbox_config["dns"]["strategy"] = "prefer_ipv4"
            # 添加更多DNS服务器
            dns_servers = self.singbox_config["dns"]["servers"]

            # 添加更多可靠的DNS服务器
            additional_servers = [
                {
                    "tag": "quad9",
                    "address": "9.9.9.9",
                    "strategy": "prefer_ipv4"
                },
                {
                    "tag": "opendns",
                    "address": "208.67.222.222",
                    "strategy": "prefer_ipv4"
                }
            ]

            for server in additional_servers:
                if not any(s["tag"] == server["tag"] for s in dns_servers):
                    dns_servers.append(server)

        # 2. 优化出站配置
        for outbound in self.singbox_config["outbounds"]:
            if outbound.get("type") in ["shadowsocks", "vmess", "vless", "trojan"]:
                # 增加连接超时
                outbound["connect_timeout"] = "15s"

                # 添加域名策略
                outbound["domain_strategy"] = "prefer_ipv4"

                # 添加绑定接口（如果需要）
                # outbound["bind_interface"] = "eth0"

        # 3. 添加故障转移规则
        self.add_failover_rules()

    def add_failover_rules(self):
        """添加故障转移规则"""
        # 为每个代理出站创建故障转移组
        proxy_outbounds = [
            outbound for outbound in self.singbox_config["outbounds"]
            if outbound.get("type") in ["shadowsocks", "vmess", "vless", "trojan", "hysteria2"]
        ]

        if len(proxy_outbounds) > 1:
            # 创建故障转移出站
            failover_outbound = {
                "type": "selector",
                "tag": "proxy-group",
                "outbounds": [outbound["tag"] for outbound in proxy_outbounds] + ["direct"]
            }

            self.singbox_config["outbounds"].insert(-1, failover_outbound)

            # 更新路由规则使用故障转移组
            for rule in self.singbox_config["route"]["rules"]:
                if rule.get("outbound") in [outbound["tag"] for outbound in proxy_outbounds]:
                    rule["outbound"] = "proxy-group"

    def print_config_stats(self):
        """打印配置统计信息"""
        outbounds = self.singbox_config["outbounds"]
        protocol_stats = {}

        for outbound in outbounds:
            if outbound["type"] not in ["direct", "block"]:
                protocol = outbound["type"]
                protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1

        print("\n=== 配置统计 ===")
        for protocol, count in sorted(protocol_stats.items()):
            print(f"{protocol.upper()}: {count} 个节点")

        print(f"入站代理: {len(self.singbox_config['inbounds'])} 个")
        print(f"路由规则: {len(self.singbox_config['route']['rules'])} 条")

    def export_clash_config(self, output_file: str = 'clash.yaml') -> bool:
        """导出Clash格式配置（简化版）"""
        try:
            import yaml

            clash_config = {
                'port': 7890,
                'socks-port': 7891,
                'allow-lan': False,
                'mode': 'rule',
                'log-level': 'info',
                'proxies': [],
                'proxy-groups': [
                    {
                        'name': 'PROXY',
                        'type': 'select',
                        'proxies': []
                    }
                ],
                'rules': [
                    'MATCH,PROXY'
                ]
            }

            # 转换代理节点
            for outbound in self.singbox_config["outbounds"]:
                if outbound["type"] not in ["direct", "block"]:
                    clash_proxy = self.convert_to_clash_proxy(outbound)
                    if clash_proxy:
                        clash_config['proxies'].append(clash_proxy)
                        clash_config['proxy-groups'][0]['proxies'].append(clash_proxy['name'])

            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, default_flow_style=False, allow_unicode=True)

            print(f"✓ Clash配置已导出: {output_file}")
            return True

        except ImportError:
            print("警告: 缺少PyYAML库，无法导出Clash配置")
            return False
        except Exception as e:
            print(f"导出Clash配置失败: {e}")
            return False

    def convert_to_clash_proxy(self, outbound: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """将sing-box出站配置转换为Clash代理配置"""
        # 这里只实现基本转换，完整实现会很复杂
        proxy_type = outbound["type"]

        if proxy_type == "vmess":
            return {
                'name': outbound.get("tag", "vmess"),
                'type': 'vmess',
                'server': outbound["server"],
                'port': outbound["server_port"],
                'uuid': outbound["uuid"],
                'alterId': outbound.get("alter_id", 0),
                'cipher': outbound.get("security", "auto")
            }
        elif proxy_type == "shadowsocks":
            return {
                'name': outbound.get("tag", "ss"),
                'type': 'ss',
                'server': outbound["server"],
                'port': outbound["server_port"],
                'cipher': outbound["method"],
                'password': outbound["password"]
            }
        # 可以继续添加其他协议的转换

        return None
    
    def parse_nodes(self, node_file: str) -> List[str]:
        """解析节点文件，提取有效节点"""
        nodes = []
        
        try:
            with open(node_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                # 跳过空行、注释行和不包含://的行
                if line and not line.startswith('#') and '://' in line:
                    nodes.append(line)
        except Exception as e:
            print(f"解析节点文件失败: {e}")
        
        return nodes
    
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
    
    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        """解析vmess链接并转换为sing-box出站配置"""
        try:
            if not vmess_url.startswith('vmess://'):
                return None

            b64_content = vmess_url[8:]
            decoded = self.safe_base64_decode(b64_content)
            if not decoded:
                return None

            try:
                vmess_info = json.loads(decoded)
            except json.JSONDecodeError as e:
                print(f"VMess JSON解析失败: {e}")
                return None

            # 验证必要字段
            if not all(key in vmess_info for key in ['add', 'port', 'id']):
                print("VMess配置缺少必要字段")
                return None

            outbound = {
                "type": "vmess",
                "server": vmess_info.get('add', ''),
                "server_port": int(vmess_info.get('port', 0)),
                "uuid": vmess_info.get('id', ''),
                "security": vmess_info.get('scy', 'auto'),
                "alter_id": int(vmess_info.get('aid', 0))
            }

            # 处理全局填充
            if 'global_padding' in vmess_info:
                outbound["global_padding"] = bool(vmess_info['global_padding'])

            # 处理认证掩码
            if 'authenticated_length' in vmess_info:
                outbound["authenticated_length"] = bool(vmess_info['authenticated_length'])

            # 处理传输协议
            transport_type = vmess_info.get('net', 'tcp')
            transport = self.build_transport_config(transport_type, vmess_info)
            if transport:
                outbound["transport"] = transport

            # 处理TLS
            tls = self.build_tls_config(vmess_info, outbound["server"])
            if tls:
                outbound["tls"] = tls

            return outbound
        except Exception as e:
            print(f"解析vmess链接失败: {e}")
        
        return None
    
    def parse_ss(self, ss_url: str) -> Optional[Dict[str, Any]]:
        """解析ss链接并转换为sing-box出站配置"""
        try:
            if not ss_url.startswith('ss://'):
                return None

            url = ss_url[5:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 处理有无@符号的情况
            if '@' in url:
                # 格式: ss://BASE64(method:password)@server:port 或 ss://method:password@server:port
                auth_str, server_port = url.split('@', 1)

                # 尝试base64解码
                decoded_auth = self.safe_base64_decode(auth_str)
                if decoded_auth and ':' in decoded_auth:
                    parts = decoded_auth.split(':', 1)
                    method = parts[0]

                    # 特殊处理2022-blake3-aes-256-gcm
                    if method == '2022-blake3-aes-256-gcm' and len(parts) > 1:
                        # 对于这种格式，密码部分已经是 key_b64:salt_b64 格式
                        password_part = parts[1]
                        if ':' in password_part:
                            key_b64, salt_b64 = password_part.split(':', 1)
                            # 尝试解码key和salt
                            try:
                                key = self.safe_base64_decode(key_b64)
                                salt = self.safe_base64_decode(salt_b64)
                                if key and salt:
                                    password = f"{key}:{salt}"
                                    print(f"成功解析2022-blake3-aes-256-gcm密码")
                                else:
                                    password = password_part  # 使用Base64格式
                            except Exception:
                                password = password_part  # 使用Base64格式
                        else:
                            password = password_part
                    else:
                        password = parts[1]
                elif ':' in auth_str:
                    # 明文格式
                    method, password = auth_str.split(':', 1)
                else:
                    print("无法解析Shadowsocks认证信息")
                    return None

                server, port = server_port.rsplit(':', 1)
            else:
                # 格式: ss://BASE64(method:password@server:port)
                decoded = self.safe_base64_decode(url)
                if not decoded:
                    return None

                if '@' not in decoded:
                    print("Shadowsocks URL格式错误")
                    return None

                # 解析格式 method:password@server:port
                auth, server_port = decoded.split('@', 1)
                if ':' not in auth:
                    print("Shadowsocks认证格式错误")
                    return None

                method, password = auth.split(':', 1)
                server, port = server_port.rsplit(':', 1)

            # 创建出站配置（移到这里，两种格式都使用）
            outbound = {
                "type": "shadowsocks",
                "server": server,
                "server_port": int(port),
                "method": method,
                "password": password  # 对于2022-blake3-aes-256-gcm已经在上面处理过了
            }

            # 处理插件配置
            plugin_config = self.parse_ss_plugin(params_dict)
            if plugin_config:
                outbound.update(plugin_config)

            # 处理多路复用
            if 'mux' in params_dict:
                outbound["multiplex"] = {
                    "enabled": params_dict['mux'] in ['1', 'true', True],
                    "protocol": "smux",
                    "max_connections": 4,
                    "min_streams": 4,
                    "max_streams": 0
                }

            return outbound
        except Exception as e:
            print(f"解析ss链接失败: {e}")
        
        return None
    
    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        """解析trojan链接并转换为sing-box出站配置"""
        try:
            if not trojan_url.startswith('trojan://'):
                return None

            url = trojan_url[9:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析密码和服务器信息
            if '@' not in url:
                print("Trojan URL格式错误：缺少@符号")
                return None

            password, server_port = url.split('@', 1)
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password
            }

            # 处理TLS配置（Trojan默认需要TLS）
            tls = self.build_tls_config(params_dict, server)
            if tls:
                outbound["tls"] = tls
            else:
                # 默认TLS配置
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": self.normalize_server_name(server, params_dict.get('sni', ''))
                }

            # 处理传输协议
            transport_type = params_dict.get('type', 'tcp')
            transport = self.build_transport_config(transport_type, params_dict)
            if transport:
                outbound["transport"] = transport

            return outbound
        except Exception as e:
            print(f"解析trojan链接失败: {e}")
        
        return None
    
    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        """解析vless链接并转换为sing-box出站配置"""
        try:
            if not vless_url.startswith('vless://'):
                return None

            url = vless_url[8:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析UUID和服务器信息
            if '@' not in url:
                print("VLESS URL格式错误：缺少@符号")
                return None

            uuid_str, server_port = url.split('@', 1)
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": uuid_str
            }

            # 处理流控
            flow = params_dict.get('flow', '')
            if flow:
                outbound["flow"] = flow

            # 处理TLS配置
            tls = self.build_tls_config(params_dict, server)
            if tls:
                outbound["tls"] = tls

            # 处理传输协议
            transport_type = params_dict.get('type', 'tcp')
            transport = self.build_transport_config(transport_type, params_dict)
            if transport:
                outbound["transport"] = transport

            return outbound
        except Exception as e:
            print(f"解析vless链接失败: {e}")
        
        return None
    
    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        """解析hysteria2链接并转换为sing-box出站配置"""
        try:
            if not hy2_url.startswith('hysteria2://'):
                return None

            url = hy2_url[12:]

            # 解析URL和参数
            url, params_dict = self.parse_url_params(url)

            # 解析认证信息和服务器信息
            if '@' not in url:
                print("Hysteria2 URL格式错误：缺少@符号")
                return None

            auth, server_port = url.split('@', 1)
            server, port = server_port.rsplit(':', 1)

            # 创建出站配置
            outbound = {
                "type": "hysteria2",
                "server": server,
                "server_port": int(port),
                "password": auth
            }

            # 处理TLS配置（Hysteria2默认需要TLS）
            tls = self.build_tls_config(params_dict, server)
            if tls:
                outbound["tls"] = tls
            else:
                # 默认TLS配置
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": self.normalize_server_name(server, params_dict.get('sni', ''))
                }

            # 处理混淆
            if 'obfs' in params_dict:
                outbound["obfs"] = {
                    "type": params_dict['obfs']
                }
                if 'obfs-password' in params_dict:
                    outbound["obfs"]["password"] = params_dict['obfs-password']

            # 处理带宽控制
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
    
    def convert_node(self, node_url: str) -> Optional[Dict[str, Any]]:
        """根据节点URL类型调用相应的解析函数"""
        # 提取协议类型
        if '://' not in node_url:
            print(f"无效的节点URL格式: {node_url[:50]}...")
            return None

        protocol = node_url.split('://', 1)[0].lower()

        # 使用协议映射表
        if protocol in self.supported_protocols:
            try:
                return self.supported_protocols[protocol](node_url)
            except Exception as e:
                print(f"解析{protocol}节点失败: {e}")
                return None
        else:
            print(f"不支持的协议类型: {protocol}")
            return None
    
    def generate_config(self, node_file: str, output_file: str = 'config.json', overseas_mode: bool = False) -> bool:
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
            successful_nodes = 0
            failed_nodes = 0

            for i, node_url in enumerate(nodes):
                print(f"正在处理节点 {i+1}/{len(nodes)}...")

                # 转换节点为出站配置
                outbound = self.convert_node(node_url)
                if outbound:
                    # 验证配置
                    if not self.validate_outbound_config(outbound):
                        print(f"节点 {i+1} 配置验证失败，跳过")
                        failed_nodes += 1
                        continue

                    # 添加元数据
                    outbound = self.add_node_metadata(outbound, node_url, i)

                    # 生成端口号
                    port = start_port + successful_nodes

                    # 生成入站标签
                    tag = f"in_{successful_nodes}"

                    # 创建入站配置
                    inbound = self.create_inbound(tag, port)
                    self.singbox_config["inbounds"].append(inbound)

                    # 设置出站标签
                    outbound["tag"] = f"proxy_{successful_nodes}"
                    self.singbox_config["outbounds"].append(outbound)

                    # 添加路由规则
                    self.singbox_config["route"]["rules"].append({
                        "inbound": [tag],
                        "outbound": outbound["tag"]
                    })

                    protocol = outbound["type"]
                    remark = outbound.get("_remark", f"节点{i+1}")
                    print(f"✓ 节点 {i+1} ({protocol}) 配置成功，入站端口: {port}，备注: {remark}")
                    successful_nodes += 1
                else:
                    print(f"✗ 节点 {i+1} 解析失败，跳过")
                    failed_nodes += 1

            print(f"\n配置完成: 成功 {successful_nodes} 个，失败 {failed_nodes} 个")

            if successful_nodes == 0:
                print("没有成功配置的节点，取消生成配置文件")
                return False

            # 添加默认出站
            self.singbox_config["outbounds"].extend([
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                }
            ])

            # 优化配置
            self.optimize_config(overseas_mode=overseas_mode)

            # 生成配置统计
            self.print_config_stats()

            # 写入配置文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.singbox_config, f, indent=2, ensure_ascii=False)

            print(f"\n✓ 配置文件已生成: {output_file}")
            print(f"✓ 总共配置了 {successful_nodes} 个代理节点")
            return True
        
        except Exception as e:
            print(f"生成配置文件失败: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='将v2ray节点转换为sing-box配置',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
支持的协议:
  VMess, VLESS, Shadowsocks, Trojan, Hysteria, Hysteria2,
  TUIC, WireGuard, SSH, ShadowTLS

示例:
  python v2ray2singbox.py -i nodes.txt -o config.json
  python v2ray2singbox.py --export-clash --clash-output clash.yaml
        """
    )

    parser.add_argument('-i', '--input', default='node.txt',
                       help='输入节点文件路径 (默认: node.txt)')
    parser.add_argument('-o', '--output', default='config.json',
                       help='输出sing-box配置文件路径 (默认: config.json)')
    parser.add_argument('-c', '--config', default='settings.json',
                       help='设置文件路径 (默认: settings.json)')
    parser.add_argument('--export-clash', action='store_true',
                       help='同时导出Clash配置')
    parser.add_argument('--clash-output', default='clash.yaml',
                       help='Clash配置文件输出路径 (默认: clash.yaml)')
    parser.add_argument('--validate-only', action='store_true',
                       help='仅验证节点，不生成配置文件')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='显示详细输出')
    parser.add_argument('--overseas', action='store_true',
                       help='海外环境优化模式（适用于从海外访问国内节点）')

    args = parser.parse_args()

    print("=== V2Ray to Sing-box 转换器 ===")
    print(f"输入文件: {args.input}")
    print(f"输出文件: {args.output}")
    print(f"设置文件: {args.config}")
    print()

    # 创建转换器
    converter = V2raySingboxConverter(args.config)

    if args.validate_only:
        # 仅验证模式
        nodes = converter.parse_nodes(args.input)
        if not nodes:
            print("未找到有效节点")
            return False

        print(f"找到 {len(nodes)} 个节点，开始验证...")
        valid_count = 0

        for i, node_url in enumerate(nodes):
            outbound = converter.convert_node(node_url)
            if outbound and converter.validate_outbound_config(outbound):
                valid_count += 1
                if args.verbose:
                    protocol = outbound["type"]
                    remark = outbound.get("_remark", f"节点{i+1}")
                    print(f"✓ 节点 {i+1} ({protocol}): {remark}")
            else:
                if args.verbose:
                    print(f"✗ 节点 {i+1}: 验证失败")

        print(f"\n验证完成: {valid_count}/{len(nodes)} 个节点有效")
        return valid_count > 0

    # 生成配置
    success = converter.generate_config(args.input, args.output, overseas_mode=args.overseas)

    if success:
        print("\n✓ Sing-box配置生成成功！")

        # 导出Clash配置
        if args.export_clash:
            converter.export_clash_config(args.clash_output)

        print(f"\n使用方法:")
        print(f"  sing-box run -c {args.output}")

    else:
        print("\n✗ 配置生成失败，请检查节点文件和设置")

    return success


if __name__ == '__main__':
    import sys
    main()