#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import json
import re
import time
import ipaddress
import ssl
import urllib.parse
import argparse
import os
import paramiko
import getpass
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

import aiohttp
import yaml
from aiohttp_socks import ProxyConnector
from tqdm.asyncio import tqdm

# ----------------------------- 配置区 -----------------------------
PROBE_URL = "http://httpbin.org/ip"
TIMEOUT = 5
CONCURRENCY = 80 # 稍微调低，保护家用路由器 NAT 表
HAS_IPV6 = False
FETCH_TIMEOUT = 30
FETCH_UA = "clash.meta/v1.18.0"

SFTP_HOST = os.getenv("SFTP_HOST", "")
SFTP_PORT = os.getenv("SFTP_PORT", "2022")
SFTP_USER = os.getenv("SFTP_USER", "")
SFTP_PASS = os.getenv("SFTP_PASS", "")
SFTP_REMOTE_DIR = "data" 

PROTOCOL_MAP = {
    "http": "http", "https": "http",
    "socks5": "socks5", "socks5h": "socks5",
    "socks4": "socks4", "socks4a": "socks4",
}

@dataclass
class ProxyEntry:
    raw: str
    protocol: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    alive: bool = False
    latency_ms: Optional[int] = None
    error: Optional[str] = None

# ----------------------------- 网络探测与获取 -----------------------------
def is_ipv6_literal(server: str) -> bool:
    try:
        ipaddress.IPv6Address(server)
        return True
    except ValueError:
        return False

async def check_local_ipv6() -> bool:
    """并发测试多个 IPv6 目标，任意一个连通即可"""
    targets = [
        ("2606:4700:4700::1111", 53),  # Cloudflare
        ("2001:4860:4860::8888", 53),  # Google
        ("2620:fe::fe", 53)            # Quad9
    ]
    async def test_one(ip, port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    results = await asyncio.gather(*(test_one(ip, port) for ip, port in targets))
    return any(results)

async def fetch_sub_url(url: str) -> str:
    print(f"🌐 正在拉取订阅: {url}")
    try:
        timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
        headers = {"User-Agent": FETCH_UA}
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(url, headers=headers, allow_redirects=True) as resp:
                if resp.status == 200:
                    return await resp.text(errors="replace")
                else:
                    print(f"❌ 拉取失败 {url}: HTTP {resp.status}")
                    return ""
    except Exception as e:
        print(f"❌ 拉取异常 {url}: {type(e).__name__}")
        return ""

# ----------------------------- 清洗与解析 -----------------------------
def sanitize_string(s) -> str:
    if not isinstance(s, str): return str(s)
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', s)
    return s.strip()

def deep_sanitize(obj):
    if isinstance(obj, str):
        return sanitize_string(obj).replace('\n', ' ').replace('\r', '')
    elif isinstance(obj, dict):
        return {sanitize_string(k): deep_sanitize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [deep_sanitize(item) for item in obj]
    else:
        return obj

def sanitize_node(node: dict) -> Optional[dict]:
    if not isinstance(node, dict): return None
    node_type = sanitize_string(node.get("type", "")).lower()
    if not node_type: return None
    server = sanitize_string(node.get("server", ""))
    port = node.get("port")
    if not server or " " in server or len(server) > 255: return None
    try:
        port = int(port)
        if port <= 0 or port > 65535: return None
    except (ValueError, TypeError): return None
    node["type"] = node_type
    node["server"] = server
    node["port"] = port
    node = deep_sanitize(node)
    if "network" in node:
        if node["network"] not in ("ws", "tcp", "grpc", "h2", "http", "quic", "none"):
            node["network"] = "tcp"
    if node_type == "ss":
        cipher = sanitize_string(node.get("cipher", "")).lower()
        if "2022" in cipher or "blake3" in cipher: return None
    if node_type == "vmess":
        if "uuid" not in node: return None
        if "alterId" not in node: node["alterId"] = 0
        if "cipher" not in node: node["cipher"] = "auto"
    return node

def parse_vmess(link: str) -> Optional[dict]:
    try:
        b64_str = link[8:]
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
        if 'add' not in data or 'port' not in data: return None
        node = {
            "name": data.get('ps', 'vmess'), "type": "vmess",
            "server": data['add'], "port": int(data['port']),
            "uuid": data['id'], "alterId": int(data.get('aid', 0)),
            "cipher": data.get('scy', 'auto'), "udp": True
        }
        if data.get('tls') == 'tls':
            node['tls'] = True
            if data.get('sni'): node['servername'] = data['sni']
        if data.get('net') == 'ws':
            node['network'] = 'ws'
            node['ws-opts'] = {}
            if data.get('path'): node['ws-opts']['path'] = data['path']
            if data.get('host'): node['ws-opts']['headers'] = {'Host': data['host']}
        return node
    except: return None

def parse_vless(link: str) -> Optional[dict]:
    try:
        parsed = urllib.parse.urlparse(link)
        if not parsed.hostname or not parsed.port: return None
        query = urllib.parse.parse_qs(parsed.query)
        node = {
            "name": urllib.parse.unquote(parsed.fragment) or "vless", "type": "vless",
            "server": parsed.hostname, "port": parsed.port, "uuid": parsed.username, "udp": True
        }
        if query.get('security') == ['tls']:
            node['tls'] = True
            if query.get('sni'): node['servername'] = query['sni'][0]
        if query.get('type') == ['ws']:
            node['network'] = 'ws'
            node['ws-opts'] = {}
            if query.get('path'): node['ws-opts']['path'] = query['path'][0]
            if query.get('host'): node['ws-opts']['headers'] = {'Host': query['host'][0]}
        return node
    except: return None

def parse_trojan(link: str) -> Optional[dict]:
    try:
        parsed = urllib.parse.urlparse(link)
        if not parsed.hostname or not parsed.port: return None
        query = urllib.parse.parse_qs(parsed.query)
        node = {
            "name": urllib.parse.unquote(parsed.fragment) or "trojan", "type": "trojan",
            "server": parsed.hostname, "port": parsed.port, "password": parsed.username, "udp": True
        }
        if query.get('sni'): node['servername'] = query['sni'][0]
        return node
    except: return None

def parse_ss(link: str) -> Optional[dict]:
    try:
        link = link.replace("ss://", "")
        main_part = link.split('#')[0]
        name = link.split('#')[1] if '#' in link else 'ss'
        if "@" in main_part:
            auth, server_part = main_part.split("@", 1)
            try: auth = base64.b64decode(auth + "==").decode('utf-8', errors='ignore')
            except: pass
            cipher, password = auth.split(":", 1) if ":" in auth else ("aes-256-gcm", auth)
            server, port = server_part.split(":")
            port = int(port.split("?")[0])
        else:
            decoded = base64.b64decode(main_part + "==").decode('utf-8', errors='ignore')
            auth, server_part = decoded.split("@", 1)
            cipher, password = auth.split(":", 1)
            server, port = server_part.split(":")
            port = int(port)
        return {
            "name": urllib.parse.unquote(name), "type": "ss",
            "server": server, "port": port, "cipher": cipher, "password": password, "udp": True
        }
    except: return None

def parse_any(text: str) -> Tuple[List[ProxyEntry], List[dict]]:
    text = text.strip()
    if not text: return [], []
    if len(text) > 40 and "://" not in text and "\n" not in text[:200]:
        try:
            clean_b64 = re.sub(r'\s+', '', text)
            clean_b64 += "=" * ((4 - len(clean_b64) % 4) % 4)
            decoded = base64.b64decode(clean_b64).decode("utf-8", errors="ignore")
            if "://" in decoded or "proxies:" in decoded: text = decoded
        except Exception: pass
    if "proxies:" in text:
        try:
            docs = list(yaml.safe_load_all(text))
            testable, passthrough = [], []
            seen = set()
            for doc in docs:
                if not isinstance(doc, dict): continue
                for node in doc.get("proxies", []):
                    clean_node = sanitize_node(node)
                    if not clean_node: continue
                    ntype = clean_node["type"]
                    if ntype in ("http", "socks5", "socks4"):
                        testable.append(ProxyEntry(
                            raw=f"{ntype}://{clean_node['server']}:{clean_node['port']}", 
                            protocol=ntype, host=clean_node["server"], port=clean_node["port"],
                            username=clean_node.get("username"), password=clean_node.get("password")
                        ))
                    else:
                        key = hashlib.md5(json.dumps(clean_node, sort_keys=True).encode()).hexdigest()
                        if key not in seen:
                            seen.add(key)
                            passthrough.append(clean_node)
            if testable or passthrough: return testable, passthrough
        except Exception: pass
    testable = []
    passthrough = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        node = None
        if line.startswith("vmess://"): node = parse_vmess(line)
        elif line.startswith("vless://"): node = parse_vless(line)
        elif line.startswith("trojan://"): node = parse_trojan(line)
        elif line.startswith("ss://"): node = parse_ss(line)
        if node:
            clean_node = sanitize_node(node)
            if clean_node:
                clean_node["name"] = f"{clean_node['type']}-{clean_node['server']}-{clean_node['port']}"
                passthrough.append(clean_node)
            continue
        if "://" in line:
            scheme, rest = line.split("://", 1)
            proto = PROTOCOL_MAP.get(scheme.lower())
            if proto:
                user = password = None
                if "@" in rest:
                    auth, rest = rest.rsplit("@", 1)
                    user, _, password = auth.partition(":")
                parts = rest.split(":")
                if len(parts) >= 2:
                    try:
                        host, port = parts[0], int(parts[1])
                        testable.append(ProxyEntry(raw=line, protocol=proto, host=host, port=port, username=user, password=password))
                    except ValueError: pass
            continue
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    host = parts[0].strip()
                    port = int(parts[1].strip())
                    user = parts[2].strip() if len(parts) >= 3 else None
                    password = parts[3].strip() if len(parts) >= 4 else None
                    testable.append(ProxyEntry(raw=line, protocol="http", host=host, port=port, username=user, password=password))
                except ValueError: pass
    return testable, passthrough

# ----------------------------- 测速与构建 -----------------------------
async def check_one(entry: ProxyEntry, sem: asyncio.Semaphore) -> ProxyEntry:
    if not HAS_IPV6 and is_ipv6_literal(entry.host):
        entry.alive = True
        entry.latency_ms = -1 
        return entry
    async with sem:
        connector = None
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT)
            if entry.protocol in ("socks5", "socks4"):
                auth = f"{entry.username}:{entry.password or ''}@" if entry.username else ""
                connector = ProxyConnector.from_url(f"{entry.protocol}://{auth}{entry.host}:{entry.port}", rdns=True)
                session_kwargs = {"connector": connector, "timeout": timeout}
                request_kwargs = {}
            else:
                session_kwargs = {"timeout": timeout, "trust_env": False}
                request_kwargs = {"proxy": f"http://{entry.host}:{entry.port}"}
                if entry.username:
                    request_kwargs["proxy_auth"] = aiohttp.BasicAuth(entry.username, entry.password or "")
            start = time.perf_counter()
            async with aiohttp.ClientSession(**session_kwargs) as session:
                async with session.get(PROBE_URL, **request_kwargs) as resp:
                    if resp.status == 200:
                        entry.alive = True
                        entry.latency_ms = int((time.perf_counter() - start) * 1000)
        except Exception: pass
        finally:
            if connector: await connector.close()
        return entry

async def check_tcp(node: dict, sem: asyncio.Semaphore) -> bool:
    if not HAS_IPV6 and is_ipv6_literal(node["server"]):
        node["_tcp_latency"] = -1
        return True
    async with sem:
        try:
            start = time.perf_counter()
            if node.get("tls") is True:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                sni = node.get("servername") or node["server"]
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(node["server"], node["port"], ssl=ssl_ctx, server_hostname=sni), timeout=TIMEOUT)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(node["server"], node["port"]), timeout=TIMEOUT)
            node["_tcp_latency"] = int((time.perf_counter() - start) * 1000)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

def node_from_entry(entry: ProxyEntry) -> dict:
    node = {
        "name": "x", "type": "socks5" if entry.protocol == "socks4" else entry.protocol,
        "server": entry.host, "port": entry.port,
    }
    if entry.protocol == "socks5": node["udp"] = True
    elif entry.protocol == "socks4": node["udp"] = False
    if entry.username:
        node["username"] = entry.username
        node["password"] = entry.password or ""
    return node

def node_key(node: dict) -> str:
    return hashlib.md5(json.dumps({k: v for k, v in node.items() if k != "name"}, sort_keys=True, default=str).encode()).hexdigest()

def dedup_nodes(nodes: List[dict]) -> List[dict]:
    seen = set()
    result = []
    for node in nodes:
        if not isinstance(node, dict): continue
        k = node_key(node)
        if k in seen: continue
        seen.add(k)
        result.append(node)
    return result

def build_yaml(nodes: List[dict]) -> str:
    clean_nodes = []
    type_groups = {}
    for i, n in enumerate(nodes, 1):
        sanitized = sanitize_node(n)
        if not sanitized: continue
        base = f"{sanitized.get('type', 'node')}-{sanitized.get('server', '?')}-{sanitized.get('port', '?')}"
        sanitized["name"] = f"{base}-{i:02d}"
        clean_nodes.append(sanitized)
        ntype = sanitized.get("type", "other").upper()
        if ntype not in type_groups: type_groups[ntype] = []
        type_groups[ntype].append(sanitized["name"])
    proxy_groups = []
    all_node_names = [n["name"] for n in clean_nodes]
    if all_node_names:
        proxy_groups.append({
            "name": "⚡ 全局自动测速", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
            "interval": 300, "tolerance": 50, "proxies": all_node_names
        })
    for ntype in sorted(type_groups.keys()):
        group_nodes = type_groups[ntype]
        proxy_groups.append({
            "name": f"⚡ {ntype} 自动测速", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
            "interval": 300, "tolerance": 50, "proxies": group_nodes
        })
        proxy_groups.append({
            "name": f"🚀 {ntype}", "type": "select", "proxies": [f"⚡ {ntype} 自动测速"] + group_nodes
        })
    main_proxies = ["DIRECT", "REJECT"]
    if all_node_names: main_proxies.append("⚡ 全局自动测速")
    for ntype in sorted(type_groups.keys()): main_proxies.append(f"🚀 {ntype}")
    proxy_groups.append({"name": "PROXY", "type": "select", "proxies": main_proxies})
    config = {
        "proxies": clean_nodes,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,PROXY"],
    }
    return yaml.dump(config, allow_unicode=True, default_flow_style=False, sort_keys=False, width=float("inf"))

# ----------------------------- SFTP 原子上传 -----------------------------
def upload_to_sftp(local_file: Path, remote_filename: str):
    print(f"\n🚀 正在准备连接云端服务器...")
    
    host = SFTP_HOST or input("SFTP 地址 (例如 fr-node-51.katabump.fr): ").strip()
    port = int(SFTP_PORT) if SFTP_PORT else int(input("SFTP 端口 (默认 2022): ").strip() or "2022")
    user = SFTP_USER or input("SFTP 用户名: ").strip()
    # 使用 getpass 隐藏密码输入
    pwd = SFTP_PASS or getpass.getpass("SFTP 密码 (输入不回显): ").strip()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pwd, timeout=10)
        sftp = ssh.open_sftp()

        try:
            sftp.stat(SFTP_REMOTE_DIR)
        except IOError:
            print(f"📁 远程目录 {SFTP_REMOTE_DIR} 不存在，正在创建...")
            sftp.mkdir(SFTP_REMOTE_DIR)

        remote_path = f"{SFTP_REMOTE_DIR}/{remote_filename}"
        tmp_remote_path = remote_path + ".tmp"
        
        print(f"⬆️ 正在上传至临时文件: /home/container/{tmp_remote_path}")
        sftp.put(str(local_file), tmp_remote_path)
        
        print(f"🔄 覆盖替换目标文件: {remote_path}")
        try:
            sftp.remove(remote_path) # 如果目标文件存在，先删除，防止 rename 报错
        except IOError:
            pass
        sftp.rename(tmp_remote_path, remote_path)
        
        print("✅ 上传成功！")
    except Exception as e:
        print(f"❌ 上传失败: {e}")
    finally:
        if 'sftp' in locals() and sftp: sftp.close()
        if ssh: ssh.close()

# ----------------------------- 主程序 -----------------------------
async def main():
    global HAS_IPV6
    parser = argparse.ArgumentParser(description="本地节点清洗与 Clash 配置生成")
    parser.add_argument("-i", "--input", default="", help="输入文件路径")
    parser.add_argument("-u", "--url", nargs="+", default=[], help="订阅链接")
    parser.add_argument("-o", "--output", default="local_cleaned.yaml", help="本地生成的文件名")
    parser.add_argument("--upload", action="store_true", help="是否上传到云端")
    parser.add_argument("--remote-file", default="cloud_cleaned.yaml", help="云端新建的文件名")
    args = parser.parse_args()

    if not args.input and not args.url:
        print("✨ 欢迎使用本地节点清洗工具 ✨")
        print("1. 输入订阅链接清洗")
        print("2. 清洗本地文件 (如 input.txt)")
        choice = input("请选择 (1 或 2): ").strip()
        
        if choice == "1":
            url = input("请粘贴你的订阅链接: ").strip()
            if url: args.url = [url]
            else: return
        elif choice == "2":
            path = input("请输入文件名 (例如 input.txt): ").strip()
            if path: args.input = path
            else: return
        else:
            print("❌ 无效的选择。")
            return
            
        local_name = input(f"请输入本地生成的文件名 (默认 {args.output}): ").strip()
        if local_name: args.output = local_name

        up_choice = input("清洗完成后是否上传到云端? (y/n): ").strip().lower()
        if up_choice == 'y':
            args.upload = True
            remote_name = input(f"请输入云端【新建】的文件名 (默认 {args.remote_file}): ").strip()
            if remote_name: args.remote_file = remote_name

    combined_raw_text = ""

    if args.input:
        input_path = Path(args.input)
        if input_path.exists():
            file_text = input_path.read_text(encoding="utf-8")
            combined_raw_text += file_text + "\n"
            print(f"📄 已读取本地文件: {args.input} ({len(file_text)} 字节)")
        else:
            print(f"⚠️ 警告: 找不到输入文件 {args.input}，将忽略。")

    if args.url:
        for u in args.url:
            url_text = await fetch_sub_url(u)
            if url_text:
                combined_raw_text += url_text + "\n"

    if not combined_raw_text.strip():
        print("❌ 错误: 没有获取到任何节点数据。")
        return

    output_path = Path(args.output)

    print("🔍 正在多路检测本地 IPv6 环境...")
    HAS_IPV6 = await check_local_ipv6()
    print(f"   IPv6 支持: {'✅ 是' if HAS_IPV6 else '❌ 否 (纯 IPv6 节点将直接放行)'}")

    print("📦 正在解析节点...")
    testable, passthrough = parse_any(combined_raw_text)
    total = len(testable) + len(passthrough)
    print(f"   解析完成: 共发现 {total} 个节点")

    if total == 0:
        print("❌ 没有找到有效节点。")
        return

    sem = asyncio.Semaphore(CONCURRENCY)

    print("\n🚀 开始并发测速 (按 Ctrl+C 可随时中止)...")
    
    # 使用 tqdm 替换原来的手动 print
    http_results = await tqdm.gather(
        *(check_one(p, sem) for p in testable), 
        desc="⚡ HTTP/SOCKS 测速", 
        unit="个"
    )
    tcp_results = await tqdm.gather(
        *(check_tcp(n, sem) for n in passthrough), 
        desc="⚡ TCP/SSL 探活", 
        unit="个"
    )
    
    print("\n✨ 测速完成，正在整理数据...")

    alive_http = [r for r in http_results if r.alive]
    alive_passthrough = [n for n, is_alive in zip(passthrough, tcp_results) if is_alive]

    all_nodes = dedup_nodes([node_from_entry(p) for p in alive_http] + alive_passthrough)
    
    yaml_text = build_yaml(all_nodes)
    output_path.write_text(yaml_text, encoding="utf-8")

    print(f"\n✅ 清洗成功！")
    print(f"   存活节点: {len(all_nodes)} / {total}")
    print(f"   本地文件已新建保存至: {output_path.absolute()}")

    if args.upload:
        upload_to_sftp(output_path, args.remote_file)
    else:
        print("\n💡 提示: 未执行上传。你可以手动用 SFTP 上传此文件。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n🛑 用户中断了测速。")
