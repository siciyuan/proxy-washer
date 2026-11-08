#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import json
import os
import re
import time
import uuid
import shutil
import ipaddress
import ssl
import urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import aiohttp
import yaml
from aiohttp_socks import ProxyConnector
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

# ----------------------------- Config -----------------------------
SECRET_UUID = os.getenv("PANEL_UUID", "e8b5a2c9-4f1d-4a6b-8c3e-2b7d9f1a6c4d")
PANEL_PATH = f"/panel/{SECRET_UUID}"

# 🚨 安全配置：后台管理密码 (默认为 admin，强烈建议在环境变量中修改)
# 启动时会把明文密码转成 SHA-256 哈希存起来，比对时也用哈希对比
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

PROXY_HOME_URL = "https://buspedia.top/line/nd30pr"
PROBE_URL = "http://httpbin.org/ip"

TIMEOUT = 5          
CONCURRENCY = 100    
PORT = 20270

FETCH_TIMEOUT = 30
FETCH_MAX_BYTES = 10 * 1024 * 1024
FETCH_UA = "clash.meta/v1.18.0"

STATE_DIR = Path("data")
STATE_DIR.mkdir(exist_ok=True)
SUB_FILE = STATE_DIR / "subscription.yaml"
CUSTOM_SUB_FILE = STATE_DIR / "cloud_cleaned.yaml"
META_FILE = STATE_DIR / "meta.json"

app = FastAPI(title="Proxy Checker & Merger")
TASKS: Dict[str, dict] = {}

PROTOCOL_MAP = {
    "http": "http", "https": "http",
    "socks5": "socks5", "socks5h": "socks5",
    "socks4": "socks4", "socks4a": "socks4",
}

HAS_IPV6 = False  

# ----------------------------- 安全依赖 (Depends) -----------------------------
async def verify_admin(x_admin_token: str = Header(None)):
    """验证管理员密码哈希，保护敏感 API"""
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Unauthorized: Missing Token")
    # 对用户传来的 Token 计算哈希进行比对
    token_hash = hashlib.sha256(x_admin_token.encode()).hexdigest()
    if token_hash != ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Token")
    return True

# ----------------------------- 网络环境探测 -----------------------------
def is_ipv6_literal(server: str) -> bool:
    try:
        ipaddress.IPv6Address(server)
        return True
    except ValueError:
        return False

async def check_local_ipv6() -> bool:
    """并发测试多个 IPv6 目标，只要有一个通就说明支持"""
    targets = [
        ("2606:4700:4700::1111", 53),  # Cloudflare DNS
        ("2001:4860:4860::8888", 53),  # Google DNS
        ("2620:fe::fe", 53),           # Quad9 DNS
        ("2001:db8::1", 53)            # 备用测试点(这里通常不通，用于极端测试)
    ]
    
    async def test_one(ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    results = await asyncio.gather(*(test_one(ip, port) for ip, port in targets))
    return any(results)

# ----------------------------- Security Sanitizer -----------------------------
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

# ... [为了节省篇幅，这里省略 Model, Parser, Checker 等部分，与之前完全一致] ...
# [请直接将原来的 dataclass 到 Task runners 之间的代码原封不动复制到这里]

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

class CheckRequest(BaseModel):
    proxies: str = ""
    texts: List[str] = []
    urls: List[str] = []
    append: bool = True

async def fetch_url(url: str, task: dict) -> Tuple[Optional[str], Optional[str]]:
    try:
        timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
        headers = {"User-Agent": FETCH_UA}
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(url, headers=headers, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None, f"HTTP {resp.status}"
                body = await resp.text(errors="replace")
                return body, None
    except Exception as exc:
        return None, f"{type(exc).__name__}"
    finally:
        task["fetch_done"] = task.get("fetch_done", 0) + 1

async def fetch_all(urls: List[str], task: dict) -> Tuple[List[str], List[dict]]:
    if not urls: return [], []
    task["fetch_total"] = len(urls)
    task["fetch_done"] = 0
    results = await asyncio.gather(*(fetch_url(u, task) for u in urls))
    contents, errors = [], []
    for url, (content, err) in zip(urls, results):
        if content is not None: contents.append(content)
        else: errors.append({"url": url, "error": err})
    return contents, errors

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

async def check_one(entry: ProxyEntry, sem: asyncio.Semaphore, task: dict) -> ProxyEntry:
    if not HAS_IPV6 and is_ipv6_literal(entry.host):
        entry.alive = True
        entry.latency_ms = -1 
        task["checked"] += 1
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
            task["checked"] += 1
        return entry

async def check_tcp(node: dict, sem: asyncio.Semaphore, task: dict) -> bool:
    if not HAS_IPV6 and is_ipv6_literal(node["server"]):
        node["_tcp_latency"] = -1
        task["checked"] += 1
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
        finally:
            task["checked"] += 1

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

def extract_existing_nodes() -> List[dict]:
    if not SUB_FILE.exists(): return []
    try:
        data = yaml.safe_load(SUB_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            proxies = data.get("proxies", [])
            return proxies if isinstance(proxies, list) else []
    except Exception: pass
    return []

def save_subscription(yaml_text: str, nodes: int, total: int, passthrough: int) -> None:
    SUB_FILE.write_text(yaml_text, encoding="utf-8")
    META_FILE.write_text(json.dumps({
        "nodes": nodes, "total": total, "passthrough": passthrough,
        "updated": int(time.time()), "size": len(yaml_text.encode()),
    }), encoding="utf-8")

def load_meta() -> dict:
    if META_FILE.exists():
        try:
            data = json.loads(META_FILE.read_text())
            if "alive" in data and "nodes" not in data: data["nodes"] = data.pop("alive")
            return data
        except Exception: pass
    return {"nodes": 0, "total": 0, "passthrough": 0, "updated": 0, "size": 0}

async def run_check(task_id: str, raw: str, urls: List[str], append: bool) -> None:
    task = TASKS[task_id]
    try:
        if urls:
            task["phase"] = "fetching"
            contents, errors = await fetch_all(urls, task)
            task["url_errors"] = errors
            if contents: raw = (raw + "\n" if raw else "") + "\n".join(contents)
        task["phase"] = "processing"
        testable, passthrough = parse_any(raw)
        task["total"] = len(testable) + len(passthrough)
        task["passthrough"] = len(passthrough)
        if not testable and not passthrough:
            task["status"] = "error"
            task["error"] = "No valid nodes found"
            return
        sem = asyncio.Semaphore(CONCURRENCY)
        http_results = await asyncio.gather(*(check_one(p, sem, task) for p in testable))
        alive_http = [r for r in http_results if r.alive]
        tcp_results = await asyncio.gather(*(check_tcp(n, sem, task) for n in passthrough))
        alive_passthrough = [n for n, is_alive in zip(passthrough, tcp_results) if is_alive]
        new_nodes = dedup_nodes([node_from_entry(p) for p in alive_http] + alive_passthrough)
        if append:
            existing = dedup_nodes(extract_existing_nodes())
            existing_keys = {node_key(n) for n in existing}
            added_nodes = [n for n in new_nodes if node_key(n) not in existing_keys]
            all_nodes = existing + added_nodes
            task["added"], task["kept"] = len(added_nodes), len(existing)
        else:
            all_nodes = new_nodes
            task["added"], task["kept"] = len(new_nodes), 0
        yaml_text = build_yaml(all_nodes)
        task["alive"] = [asdict(p) for p in alive_http] + [
            {"protocol": n["type"], "host": n["server"], "port": n["port"], "latency_ms": n.get("_tcp_latency", -1), "alive": True}
            for n in alive_passthrough
        ]
        task["sub_total"] = len(all_nodes)
        task["yaml"] = yaml_text
        task["status"] = "done"
        save_subscription(yaml_text, len(all_nodes), len(testable) + len(passthrough), len(passthrough))
    except Exception as e:
        import traceback
        traceback.print_exc()
        task["status"] = "error"
        task["error"] = str(e)


def _new_task() -> dict:
    return {
        "status": "running", "phase": "starting", "total": 0, "checked": 0,
        "passthrough": 0, "alive": [], "yaml": "", "error": None,
        "added": 0, "kept": 0, "sub_total": 0, "fetch_total": 0, "fetch_done": 0, "url_errors": [],
    }

# ----------------------------- API 路由 (加入安全保护) -----------------------------

@app.post(PANEL_PATH + "/api/check", dependencies=[Depends(verify_admin)])
async def start_check(req: CheckRequest):
    """🚨 需要鉴权：开始测速"""
    task_id = uuid.uuid4().hex[:12]
    TASKS[task_id] = _new_task()
    combined_proxies = req.proxies
    if req.texts: combined_proxies += "\n" + "\n".join(req.texts)
    asyncio.create_task(run_check(task_id, combined_proxies, req.urls, req.append))
    return {"task_id": task_id}

@app.get(PANEL_PATH + "/api/status/{task_id}", dependencies=[Depends(verify_admin)])
async def get_status(task_id: str):
    """🚨 需要鉴权：获取测速进度"""
    task = TASKS.get(task_id)
    if not task: raise HTTPException(404, "Task not found")
    resp = {k: task[k] for k in ["status", "phase", "total", "checked", "alive", "passthrough", "added", "kept", "sub_total", "fetch_total", "fetch_done", "url_errors"]}
    if task["status"] == "error": resp["error"] = task["error"]
    return resp

@app.get(PANEL_PATH + "/api/subscription/info")
async def sub_info():
    """⚠️ 可公开：只读信息，显示在页面头部"""
    meta = load_meta()
    meta["url"] = PANEL_PATH + "/sub"
    return meta

@app.get(PANEL_PATH + "/sub")
@app.get(PANEL_PATH + "/sub.yaml")
async def subscription():
    """⚠️ 必须公开：客户端拉取总表，无需鉴权"""
    if not SUB_FILE.exists(): return Response("# No subscription yet.\n", media_type="text/yaml")
    return Response(SUB_FILE.read_text(encoding="utf-8"), media_type="text/yaml; charset=utf-8")

@app.get(PANEL_PATH + "/sub/cleaned")
@app.get(PANEL_PATH + "/sub/cleaned.yaml")
async def custom_subscription():
    """⚠️ 必须公开：客户端拉取清洗表，无需鉴权"""
    if not CUSTOM_SUB_FILE.exists(): 
        return Response("# Custom subscription not found yet.\n", media_type="text/yaml")
    return Response(CUSTOM_SUB_FILE.read_text(encoding="utf-8"), media_type="text/yaml; charset=utf-8")

@app.delete(PANEL_PATH + "/api/subscription", dependencies=[Depends(verify_admin)])
async def clear_subscription():
    """🚨 需要鉴权：清空订阅 (防破坏核心)"""
    for f in (SUB_FILE, META_FILE):
        if f.exists(): f.unlink()
    return {"ok": True}

@app.get(PANEL_PATH, response_class=HTMLResponse)
async def index():
    html = HTML_PAGE.replace("__BASE_PATH__", PANEL_PATH)
    return html

@app.get("/")
async def proxy_home(request: str = ""):
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(PROXY_HOME_URL, headers={"User-Agent": FETCH_UA}) as resp:
                content = await resp.text(errors="ignore")
                return HTMLResponse(content=content, status_code=resp.status)
    except Exception:
        return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)

async def startup_clean():
    global HAS_IPV6
    HAS_IPV6 = await check_local_ipv6()
    print(f"\n[Auto-Clean] IPv6 测试结果: {'✅ 已连通' if HAS_IPV6 else '❌ 无 IPv6'}")
    if not SUB_FILE.exists(): return
    try:
        text = SUB_FILE.read_text(encoding="utf-8")
        testable, passthrough = parse_any(text)
        total_nodes = len(testable) + len(passthrough)
        if total_nodes == 0:
            if len(text.strip()) > 20:
                backup_file = SUB_FILE.with_name("subscription_corrupted.yaml.bak")
                shutil.move(SUB_FILE, backup_file)
                save_subscription("proxies:\n\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\n\nrules:\n  - MATCH,PROXY\n", 0, 0, 0)
            return
        task = {"checked": 0, "total": total_nodes}
        async def monitor_progress():
            last_checked = -1
            while task["checked"] < total_nodes:
                if task["checked"] != last_checked:
                    print(f"[Auto-Clean] {task['checked']} / {total_nodes}", end='\r')
                    last_checked = task["checked"]
                await asyncio.sleep(0.2)
        monitor_task = asyncio.create_task(monitor_progress())
        sem = asyncio.Semaphore(CONCURRENCY)
        http_results = await asyncio.gather(*(check_one(p, sem, task) for p in testable))
        alive_http = [r for r in http_results if r.alive]
        tcp_results = await asyncio.gather(*(check_tcp(n, sem, task) for n in passthrough))
        alive_passthrough = [n for n, is_alive in zip(passthrough, tcp_results) if is_alive]
        monitor_task.cancel()
        new_nodes = dedup_nodes([node_from_entry(p) for p in alive_http] + alive_passthrough)
        yaml_text = build_yaml(new_nodes)
        SUB_FILE.write_text(yaml_text, encoding="utf-8")
        save_subscription(yaml_text, len(new_nodes), total_nodes, len(passthrough))
        print(f"\n[Auto-Clean] ✅ 完成！{len(new_nodes)}/{total_nodes} 存活\n")
    except Exception as e:
        print(f"\n[Auto-Clean] ❌ 异常: {e}\n")

# ----------------------------- Frontend (加入 token 鉴权逻辑) -----------------------------
HTML_PAGE = r"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Proxy Checker & Clash Merger</title><style>body{font-family:-apple-system,sans-serif;max-width:1100px;margin:30px auto;padding:20px;background:#0f1419;color:#e6e6e6}h1{color:#4ade80;margin:0 0 5px 0}h2{color:#4ade80;margin:0 0 10px 0;font-size:18px}code{background:#1a1f2e;padding:2px 6px;border-radius:4px;color:#22d3ee}textarea{width:100%;padding:10px;background:#1a1f2e;color:#e6e6e6;border:1px solid #2d3748;border-radius:6px;font-family:monospace;font-size:13px;box-sizing:border-box}textarea.tall{height:150px}textarea.short{height:70px}input[type="file"]{background:#1a1f2e;color:#9ca3af;padding:8px;border-radius:6px;border:1px dashed #4ade80;width:100%;margin-bottom:15px}button{background:#4ade80;color:#0f1419;border:none;padding:10px 20px;border-radius:6px;font-weight:bold;cursor:pointer;font-size:14px}button:disabled{background:#4b5563;color:#9ca3af;cursor:not-allowed}button.secondary{background:#2d3748;color:#e6e6e6}button.small{padding:6px 12px;font-size:12px}.card{background:#1a1f2e;border-radius:8px;padding:15px 20px;margin:20px 0;border:1px solid #2d3748}.url-row{display:flex;gap:10px;align-items:center;margin-top:10px}.url-row code{flex:1;padding:8px 12px;font-size:13px}.bar{height:8px;background:#1a1f2e;border-radius:4px;margin:15px 0;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#4ade80,#22d3ee);width:0%;transition:width .3s}.status{display:flex;justify-content:space-between;font-size:14px;color:#9ca3af}.muted{color:#9ca3af;font-size:13px}table{width:100%;border-collapse:collapse;margin-top:15px;font-size:13px}th,td{padding:8px;text-align:left;border-bottom:1px solid #2d3748}th{background:#1a1f2e;color:#9ca3af}.alive{color:#4ade80}.dead{color:#ef4444}.row{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap}label{display:inline-flex;align-items:center;gap:6px;color:#9ca3af;font-size:13px;cursor:pointer}.field-label{font-size:13px;color:#9ca3af;margin:15px 0 5px;display:block}</style></head><body><h1>🔍 Proxy Checker & Clash Merger</h1><p>支持通用链接、纯 IP 列表解析、极速测活，并强制按协议整理策略组。</p><label class="field-label">Proxy list / Clash YAML / 通用链接 / 纯 IP:PORT (可粘贴，也可上传文件)</label><textarea id="input-test" class="tall" placeholder="Paste proxies, Clash YAML, plain text links, or IP:PORT lists..."></textarea><input type="file" id="file-test" multiple accept=".yaml,.yml,.txt"><label class="field-label">Subscription URLs (可选)</label><textarea id="urls-test" class="short" placeholder="https://example.com/sub"></textarea><div class="row" style="margin-top:15px"><button id="btn-test">▶ 开始测速与整理分组</button><label><input type="checkbox" id="append-test" checked> 保留现有节点</label><span id="elapsed-test" class="muted"></span></div><div class="card" id="sub-card"><div style="display:flex;justify-content:space-between;align-items:center"><h2 style="margin:0">📡 Subscription</h2><button class="secondary small" onclick="clearSub()">Clear</button></div><div id="sub-info" class="muted" style="margin:10px 0">Loading...</div><div class="url-row"><code id="sub-url">-</code><button class="secondary small" onclick="copySub(event)">Copy</button></div></div><div id="progress-section" style="display:none"><div class="status"><span id="phase-label">Progress</span><span id="prog-text">0 / 0</span></div><div class="bar"><div class="bar-fill" id="bar-fill"></div></div></div><div id="results"></div><script>
const BASE_PATH="__BASE_PATH__";const subUrl=window.location.origin+BASE_PATH+'/sub';document.getElementById('sub-url').textContent=subUrl;let currentTaskId=null,pollTimer=null,startTime=null;

// 🚨 安全管理：获取并缓存 Admin Token (密码明文，由浏览器保存，发请求后由后端比对 hash)
let adminToken = sessionStorage.getItem('admin_token');

// 封装的 fetch 函数，自动处理 401 并拦截重新输入密码
async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (adminToken) {
        options.headers['X-Admin-Token'] = adminToken;
    }
    const res = await fetch(url, options);
    if (res.status === 401 || res.status === 403) {
        const pwd = prompt("🔒 此操作需要管理员权限，请输入后台密码:");
        if (pwd) {
            adminToken = pwd;
            sessionStorage.setItem('admin_token', pwd);
            return apiFetch(url, options); // 递归重试
        } else {
            throw new Error("Unauthorized: 取消输入密码");
        }
    }
    return res;
}

async function readFiles(inputId){const input=document.getElementById(inputId);const texts=[];for(let i=0;i<input.files.length;i++){texts.push(await input.files[i].text())}return texts}
async function refreshSubInfo(){try{const res=await apiFetch(BASE_PATH+'/api/subscription/info');const d=await res.json();if(!d.updated){document.getElementById('sub-info').textContent='No subscription yet.';return}const t=new Date(d.updated*1000).toLocaleString();document.getElementById('sub-info').innerHTML=`Nodes: <b class="alive">${d.nodes}</b> · Size: ${(d.size/1024).toFixed(1)} KB · Updated: ${t}`}catch(e){document.getElementById('sub-info').textContent='Load info failed.'}}
function copySub(ev){navigator.clipboard.writeText(subUrl).then(()=>{const btn=ev.target;const old=btn.textContent;btn.textContent='✓ Copied';setTimeout(()=>btn.textContent=old,1200)})}
async function clearSub(){if(!confirm('Clear the current subscription?'))return; try { await apiFetch(BASE_PATH+'/api/subscription',{method:'DELETE'}); refreshSubInfo(); } catch(e) { alert("清空失败: " + e.message); }}
document.getElementById('btn-test').onclick=async()=>{const text=document.getElementById('input-test').value.trim();const texts=await readFiles('file-test');const urls=document.getElementById('urls-test').value.split('\n').map(s=>s.trim()).filter(s=>s.startsWith('http'));if(!text&&!texts.length&&!urls.length){alert('请填入内容或上传文件。');return}startTask({endpoint:BASE_PATH+'/api/check',body:{proxies:text,texts:texts,urls:urls,append:document.getElementById('append-test').checked},button:document.getElementById('btn-test'),elapsed:document.getElementById('elapsed-test')})};
async function startTask({endpoint,body,button,elapsed}){button.disabled=true;document.getElementById('results').innerHTML='';document.getElementById('progress-section').style.display='block';document.getElementById('bar-fill').style.width='0%';document.getElementById('phase-label').textContent='Starting';elapsed.textContent='';startTime=Date.now();try { const res = await apiFetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); const data=await res.json();currentTaskId=data.task_id;pollTimer=setInterval(()=>poll({button,elapsed}),700); } catch(e) { alert("请求失败: " + e.message); button.disabled=false; document.getElementById('phase-label').textContent='Error'; }}
async function poll({button,elapsed}){try{const res=await apiFetch(BASE_PATH+'/api/status/'+currentTaskId);const data=await res.json();if(!data||!data.status)throw new Error("Invalid API response");const phaseLabel=document.getElementById('phase-label');let pct=0,progText='';if(data.phase==='fetching'&&data.fetch_total){phaseLabel.textContent='Fetching URLs';pct=(data.fetch_done/data.fetch_total)*100;progText=data.fetch_done+' / '+data.fetch_total}else if(data.phase==='processing'&&data.total){phaseLabel.textContent='Testing & TCP Probing';pct=(data.checked/data.total)*100;progText=data.checked+' / '+data.total}else if(data.phase==='starting'){phaseLabel.textContent='Starting';progText='...'}else{phaseLabel.textContent='Done';pct=100;progText=(data.checked||0)+' / '+(data.total||0)}document.getElementById('bar-fill').style.width=pct+'%';document.getElementById('prog-text').textContent=progText;elapsed.textContent=((Date.now()-startTime)/1000).toFixed(1)+'s';if(data.status==='done'||data.status==='error'){clearInterval(pollTimer);button.disabled=false;if(data.status==='error'){document.getElementById('results').innerHTML='<p class="dead">Error: '+(data.error||'Unknown')+'</p>';return}refreshSubInfo();let html='';html+=`<p class="muted">新增 <b class="alive">${data.added||0}</b> 个可用节点 · 保留了 <b>${data.kept||0}</b> 个原有节点 · 文件里共 <b>${data.sub_total||0}</b> 个节点</p>`;html+=`<p class="alive">✅ 已在文件中按协议自动生成分组及专属测速组！</p>`;const aliveList=data.alive||[];html+=`<h2>存活节点预览 (前 ${aliveList.length} 个)</h2>`;if(aliveList.length){html+='<table><tr><th>#</th><th>Type</th><th>Host</th><th>Port</th><th>Latency</th></tr>';aliveList.forEach((p,i)=>{const latencyText=p.latency_ms===-1?'IPv6 免测':(p.latency_ms!=null?p.latency_ms+' ms':'—');html+=`<tr><td>${i+1}</td><td>${escapeHtml(p.protocol)}</td><td>${escapeHtml(String(p.host))}</td><td>${p.port}</td><td class="alive">${latencyText}</td></tr>`});html+='</table>'}document.getElementById('results').innerHTML=html}}catch(err){clearInterval(pollTimer);button.disabled=false;document.getElementById('phase-label').textContent='Error';document.getElementById('results').innerHTML='<p class="dead">请求后端状态失败：' + err.message + '</p>'}}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}refreshSubInfo();</script></body></html>"""

if __name__ == "__main__":
    asyncio.run(startup_clean())
    import uvicorn
    print(f"🚀 Server starting on port {PORT}")
    print(f"🔒 Secure Panel URL: http://0.0.0.0:{PORT}{PANEL_PATH}")
    print(f"📡 Main Sub URL:     http://0.0.0.0:{PORT}{PANEL_PATH}/sub")
    print(f"✨ Custom Sub URL:   http://0.0.0.0:{PORT}{PANEL_PATH}/sub/cleaned")
    print(f"🔑 Admin Password:   {ADMIN_PASSWORD} (Please change via ADMIN_PASSWORD env)")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
