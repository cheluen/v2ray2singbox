#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import urllib.parse
import sys

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
        
        # 设置WebSocket头部
        headers = {}
        if 'host' in params_dict and params_dict.get('host'):
            headers["Host"] = params_dict['host']
        
        # 添加User-Agent头部
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        if headers:
            transport["headers"] = headers
        
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
    if len(sys.argv) > 1:
        # 如果提供了命令行参数，使用它作为VLESS URL
        vless_url = sys.argv[1]
        print("=== 解析用户提供的VLESS节点 ===")
        config = parse_vless_url(vless_url)
        if config:
            print("生成的sing-box配置:")
            print(json.dumps(config, indent=2, ensure_ascii=False))
    else:
        # 使用示例节点进行测试
        print("=== 使用示例节点测试 ===")
        print("用法: python3 test_vless.py 'vless://your-vless-url-here'")
        print()
        
        # 示例节点（非真实节点）
        example_url = "vless://12345678-1234-1234-1234-123456789012@example.com:443?encryption=none&security=none&type=ws&host=example.com&path=/test#example-node"
        config = parse_vless_url(example_url)
        if config:
            print("生成的sing-box配置:")
            print(json.dumps(config, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
