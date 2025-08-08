#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import urllib.parse

def parse_vless_url(url):
    """解析VLESS URL并显示详细信息"""
    print(f"原始URL: {url}")
    print()
    
    if not url.startswith('vless://'):
        print("错误：不是有效的VLESS URL")
        return None
    
    # 移除协议前缀
    url_content = url[8:]
    
    # 分离UUID和服务器信息
    if '@' not in url_content:
        print("错误：URL格式不正确，缺少@符号")
        return None
    
    uuid_str, server_info = url_content.split('@', 1)
    print(f"UUID: {uuid_str}")
    
    # 处理备注信息
    if '#' in server_info:
        server_info, remark = server_info.split('#', 1)
        remark = urllib.parse.unquote(remark)
        print(f"备注: {remark}")
    else:
        remark = ''
    
    # 处理查询参数
    if '?' in server_info:
        server_port, params = server_info.split('?', 1)
        params_list = params.split('&')
        params_dict = {}
        for item in params_list:
            if '=' in item:
                k, v = item.split('=', 1)
                params_dict[k] = urllib.parse.unquote(v)
    else:
        server_port = server_info
        params_dict = {}
    
    # 解析服务器和端口
    server, port = server_port.rsplit(':', 1)
    
    print(f"服务器: {server}")
    print(f"端口: {port}")
    print("参数:")
    for k, v in params_dict.items():
        print(f"  {k}: {v}")
    print()
    
    # 生成sing-box配置
    config = {
        "type": "vless",
        "server": server,
        "server_port": int(port),
        "uuid": uuid_str
    }
    
    # 处理传输协议
    transport_type = params_dict.get('type', '')
    if transport_type == 'ws':
        transport = {
            "type": "ws",
            "path": params_dict.get('path', '/')
        }
        if 'host' in params_dict and params_dict.get('host'):
            transport["headers"] = {"Host": params_dict['host']}
        config["transport"] = transport
    
    # 处理安全类型
    security = params_dict.get('security', 'none')
    if security == 'tls':
        tls = {
            "enabled": True,
            "server_name": params_dict.get('sni', params_dict.get('host', server)),
            "insecure": False
        }
        config["tls"] = tls
    
    return config

def main():
    # 测试你的VLESS URL
    vless_urls = [
        "vless://69614ecf-fe1a-4ab5-8b35-0f731b0913fb@jiasu.bxvpn.xyz:2052?encryption=none&security=none&type=ws&host=baofengxuemeiguo.373799.xyz&path=%2F#%E7%BE%8E%E5%9B%BD%2B01%2B%E8%A7%A3%E9%94%81%7C%E4%B8%89%E7%BD%91%E4%BC%98%E5%8C%96%2B1.0x"
    ]
    
    for i, url in enumerate(vless_urls, 1):
        print(f"=== 测试节点 {i} ===")
        config = parse_vless_url(url)
        if config:
            print("生成的sing-box配置:")
            print(json.dumps(config, indent=2, ensure_ascii=False))
        print()

if __name__ == '__main__':
    main()
