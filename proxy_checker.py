import asyncio
import atexit
import base64
import binascii
import hashlib
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from collections import Counter
from typing import Optional, Tuple, List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote, urlencode, quote

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Сторонние библиотеки
try:
    import aiohttp
    import requests
    from tqdm.asyncio import tqdm_asyncio
    from tqdm import tqdm
    from colorama import init, Fore, Style
    import urllib3
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    init(autoreset=True)
except ImportError as e:
    print(f"❌ Ошибка: Не установлены необходимые библиотеки. ({e})")
    print("👉 Выполните: pip install aiohttp requests tqdm colorama")
    sys.exit(1)

# ================== КОНФИГУРАЦИЯ ==================

KEYS_DIR = "keys"
OUT_DIR = "output"
SYSTEM = platform.system()

# Используем HTTPS для реалистичной проверки TLS
PING_URL = "https://cp.cloudflare.com/"
GEO_URL = "http://ip-api.com/json/"
TIMEOUT_SEC = 10
BATCH_SIZE = 60 if SYSTEM == "Windows" else 120 
STARTUP_TIMEOUT = 15.0

SING_VER = "1.11.4"
CORE_NAME = "sing-box.exe" if SYSTEM == "Windows" else "sing-box"

SING_URLS = {
    "Windows": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-windows-amd64.zip",
    "Linux": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-linux-amd64.tar.gz",
    "Darwin": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-darwin-amd64.tar.gz"
}

ACTIVE_PROCESSES = []

def cleanup_processes():
    """Гарантированное убийство процессов и сброс сети"""
    for p in ACTIVE_PROCESSES:
        try:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=1.0)  # Увеличили таймаут
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=0.5)
        except (ProcessLookupError, OSError, ValueError):
            pass
    
    # На Windows дополнительно убить все sing-box процессы, если остались зомби
    if SYSTEM == "Windows":
        try:
            subprocess.run(["taskkill", "/F", "/IM", CORE_NAME], 
                         capture_output=True, check=False)
        except:
            pass

atexit.register(cleanup_processes)

# ================== УТИЛИТЫ ==================

def get_flag_emoji(cc: str) -> str:
    if not cc or len(cc) != 2 or cc == "XX":
        return "🏳️"
    cc = cc.upper()
    try:
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except (ValueError, TypeError):
        return "🏳️"

def robust_base64_decode(s: str) -> str:
    if not s: 
        return ""
    s = s.strip()
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += '=' * (4 - padding)
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except (binascii.Error, ValueError):
        return ""
    except UnicodeDecodeError:
        return ""

def find_free_port_block(size: int) -> int:
    for _ in range(50):
        start = random.randint(20000, 55000)
        if is_port_free(start) and is_port_free(start + size - 1):
            return start
    raise RuntimeError("Не удалось найти свободный блок портов")

def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def clean_url(link: str) -> str:
    try:
        link = link.strip()
        if '#' in link:
            link = link.split('#')[0]
        return link
    except (AttributeError, TypeError):
        return link

def ensure_core():
    if os.path.exists(CORE_NAME):
        return

    url = SING_URLS.get(SYSTEM)
    if not url:
        print(f"❌ Ваша ОС ({SYSTEM}) не поддерживается.")
        sys.exit(1)

    print(f"{Fore.YELLOW}[*] Скачивание Sing-box v{SING_VER}...{Style.RESET_ALL}")
    try:
        import zipfile
        import tarfile
        
        local_filename = "singbox_archive"
        urllib.request.urlretrieve(url, local_filename)

        if url.endswith('.zip'):
            with zipfile.ZipFile(local_filename, "r") as z:
                for f in z.namelist():
                    if f.endswith("sing-box.exe") or (not f.endswith(".exe") and f.endswith("sing-box")):
                        with open(CORE_NAME, "wb") as fo:
                            fo.write(z.read(f))
                        break
        else:
            with tarfile.open(local_filename, "r:gz") as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        if f:
                            with open(CORE_NAME, "wb") as fo:
                                fo.write(f.read())
                        break
        
        if SYSTEM != "Windows":
            os.chmod(CORE_NAME, 0o755)
        
        if os.path.exists(local_filename):
            os.remove(local_filename)
            
        print(f"{Fore.GREEN}[✓] Sing-box установлен.{Style.RESET_ALL}")

    except (OSError, IOError, zipfile.BadZipFile, tarfile.TarError) as e:
        print(f"❌ Ошибка установки ядра: {e}")
        sys.exit(1)

# ================== ПАРСЕР ==================

def parse_proxy(link: str, tag: str) -> Tuple[Optional[dict], Optional[str], Optional[str], Optional[int]]:
    try:
        link = link.strip()
        if not link: 
            return None, None, None, None
        
        remark = ""
        if '#' in link:
            link, remark = link.split('#', 1)
            remark = unquote(remark)
        
        outbound = {}
        proto = "Unknown"
        r_host, r_port = None, None

        # --- VMESS ---
        if link.startswith("vmess://"):
            proto = "VMess"
            try:
                b64 = link[8:]
                j = json.loads(robust_base64_decode(b64))
                
                r_host = j.get("add") or j.get("host") or j.get("ip")
                try: 
                    r_port = int(j.get("port") or j.get("server_port") or 443)
                except (ValueError, TypeError): 
                    return None, None, None, None

                outbound = {
                    "type": "vmess",
                    "tag": tag,
                    "server": r_host,
                    "server_port": r_port,
                    "uuid": j.get("id") or j.get("uuid"),
                    "security": "auto"
                }
                
                net = j.get("net", "tcp").lower()
                type_header = j.get("type", "none").lower()
                host_header = j.get("host", "")
                path_header = j.get("path", "/")

                if net in ["ws", "websocket"]:
                    outbound["transport"] = {
                        "type": "ws",
                        "path": path_header,
                        "headers": {"Host": host_header} if host_header else {}
                    }
                elif net == "grpc":
                    outbound["transport"] = {
                        "type": "grpc",
                        "service_name": path_header or "grpc"
                    }
                elif net in ["h2", "http"]:
                    outbound["transport"] = {
                        "type": "http",
                        "host": [host_header] if host_header else [],
                        "path": path_header
                    }
                
                tls_val = str(j.get("tls", "")).lower()
                if tls_val in ["tls", "1", "true"]:
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": j.get("sni") or host_header or r_host,
                        "insecure": True
                    }
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                logger.debug(f"VMess parse error: {e}")
                return None, None, None, None

        # --- VLESS / TROJAN ---
        elif link.startswith(("vless://", "trojan://")):
            is_trojan = link.startswith("trojan://")
            proto = "Trojan" if is_trojan else "VLESS"
            
            try:
                u = urlparse(link)
                q = parse_qs(u.query)
                r_host, r_port = u.hostname, u.port
                if not r_host or not r_port: 
                    return None, None, None, None
                
                outbound = {
                    "type": "trojan" if is_trojan else "vless",
                    "tag": tag,
                    "server": r_host,
                    "server_port": r_port
                }

                if is_trojan:
                    outbound["password"] = unquote(u.username or "")
                else:
                    outbound["uuid"] = u.username
                    outbound["flow"] = q.get("flow", [""])[0]

                type_net = q.get("type", ["tcp"])[0]
                if type_net == "ws":
                    outbound["transport"] = {
                        "type": "ws",
                        "path": q.get("path", ["/"])[0],
                        "headers": {"Host": q.get("host", [""])[0]}
                    }
                elif type_net == "grpc":
                    outbound["transport"] = {
                        "type": "grpc",
                        "service_name": q.get("serviceName", [""])[0]
                    }
                elif type_net == "http":
                    outbound["transport"] = {
                        "type": "http",
                        "path": q.get("path", ["/"])[0],
                        "host": [q.get("host", [""])[0]]
                    }

                sec = q.get("security", ["tls" if is_trojan else "none"])[0]
                sni = q.get("sni", [""])[0] or q.get("host", [""])[0] or r_host

                if sec == "tls":
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": sni,
                        "insecure": True
                    }
                elif sec == "reality":
                    pbk = q.get("pbk", [""])[0]
                    sid = q.get("sid", [""])[0]
                    
                    if not pbk: 
                        return None, None, None, None
                    
                    outbound["tls"] = {
                        "enabled": True,
                        "server_name": sni,
                        "reality": {
                            "enabled": True,
                            "public_key": pbk,
                            "short_id": sid
                        },
                        "utls": {"enabled": True, "fingerprint": q.get("fp", ["chrome"])[0]}
                    }
            except (ValueError, AttributeError) as e:
                logger.debug(f"VLESS/Trojan parse error: {e}")
                return None, None, None, None

        # --- SHADOWSOCKS ---
        elif link.startswith("ss://"):
            proto = "Shadowsocks"
            try:
                raw = link[5:]
                if '@' in raw:
                    userinfo, hostport = raw.rsplit('@', 1)
                    r_host, port_str = hostport.split(':')
                    r_port = int(port_str)
                    
                    if ':' not in userinfo:
                        userinfo = robust_base64_decode(userinfo)
                    
                    if ':' not in userinfo: 
                        return None, None, None, None
                    method, password = userinfo.split(':', 1)
                else:
                    decoded = robust_base64_decode(raw)
                    if '@' in decoded:
                        userinfo, hostport = decoded.rsplit('@', 1)
                        r_host, port_str = hostport.split(':')
                        r_port = int(port_str)
                        method, password = userinfo.split(':', 1)
                    else:
                        return None, None, None, None

                outbound = {
                    "type": "shadowsocks",
                    "tag": tag,
                    "server": r_host,
                    "server_port": r_port,
                    "method": method,
                    "password": unquote(password)
                }
            except (ValueError, IndexError, UnicodeDecodeError) as e:
                logger.debug(f"Shadowsocks parse error: {e}")
                return None, None, None, None

        # --- HYSTERIA 2 ---
        elif link.startswith(("hy2://", "hysteria2://")):
            proto = "Hysteria2"
            try:
                u = urlparse(link)
                r_host, r_port = u.hostname, u.port
                outbound = {
                    "type": "hysteria2",
                    "tag": tag,
                    "server": r_host,
                    "server_port": r_port,
                    "password": unquote(u.username or ""),
                    "tls": {
                        "enabled": True,
                        "server_name": parse_qs(u.query).get("sni", [r_host])[0],
                        "insecure": True
                    }
                }
            except (ValueError, AttributeError) as e:
                logger.debug(f"Hysteria2 parse error: {e}")
                return None, None, None, None
            
        if not outbound or not r_host or not r_port:
            return None, None, None, None
            
        return outbound, proto, r_host, r_port

    except Exception as e:
        logger.warning(f"Unexpected parse error for link starting with {link[:10]}...: {e}")
        return None, None, None, None

# ================== ASYNC CHECKER ==================

async def check_proxy_http(session: aiohttp.ClientSession, port: int, item: dict, my_ip: str) -> dict:
    proxy_url = f"http://127.0.0.1:{port}"
    result = {"ok": False, "msg": "", "cc": "XX", "ping": 0, "item": item}
    
    try:
        t0 = time.time()
        async with session.get(PING_URL, proxy=proxy_url, timeout=TIMEOUT_SEC, allow_redirects=False, ssl=False) as resp:
            ping = int((time.time() - t0) * 1000)
            
            if resp.status not in [200, 204]:
                result["msg"] = f"HTTP {resp.status}"
                return result
            
            result["ping"] = ping
            
            try:
                async with session.get(GEO_URL, proxy=proxy_url, timeout=5, ssl=False) as geo_resp:
                    data = await geo_resp.json()
                    remote_ip = data.get("query", "")
                    cc = data.get("countryCode", "XX")
                    
                    if my_ip and remote_ip == my_ip:
                        result["msg"] = "IP Leak"
                        return result
                    
                    result["ok"] = True
                    result["cc"] = cc
                    result["msg"] = "OK"
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError, KeyError):
                result["ok"] = True
                result["msg"] = "No Geo"
                
    except asyncio.TimeoutError:
        result["msg"] = "Timeout"
    except aiohttp.ClientConnectionError:
        result["msg"] = "Conn Error"
    except aiohttp.ClientResponseError as e:
        result["msg"] = f"HTTP {e.status}"
    except aiohttp.ClientError as e:
        result["msg"] = f"Network Error"
    except Exception as e:
        logger.error(f"Unexpected check error for port {port}: {e}")
        result["msg"] = "Error"
        
    return result

async def run_singbox_batch(chunk: List[dict], my_ip: str, pbar: tqdm):
    try:
        start_port = find_free_port_block(len(chunk))
    except RuntimeError:
        for item in chunk: 
            item['result'] = (False, "No Ports", "XX")
        pbar.update(len(chunk))
        return

    inbounds = []
    outbounds = []
    rules = []
    
    for i, item in enumerate(chunk):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = item['tag']
        
        inbounds.append({
            "type": "mixed",
            "tag": in_tag,
            "listen": "127.0.0.1",
            "listen_port": port,
            "sniff": False
        })
        outbounds.append(item['config'])
        rules.append({"inbound": in_tag, "outbound": out_tag})

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "dns", "tag": "dns-out"})
    
# Найдите эту строку в run_singbox_batch():
    config = {
        "log": {"level": "fatal", "output": "box.log"},
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "tls://8.8.8.8",  # Через TLS, не системный
                    "strategy": "ipv4_only",
                    "detour": "direct"
                }
            ],
            "final": "google",
            "independent_cache": True,
            "disable_cache": False
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "auto_detect_interface": True,  # <-- ОБЯЗАТЕЛЬНО True!
            "final": "direct",
            "default_interface": ""  # Пусто = автоопределение
        }
    }
    
    cfg_file = f"temp_cfg_{start_port}.json"
    
    try:
        with open(cfg_file, 'w') as f:
            json.dump(config, f)
    except (OSError, IOError) as e:
        logger.error(f"Failed to write config file {cfg_file}: {e}")
        for item in chunk: 
            item['result'] = (False, f"IO Error", "XX")
        pbar.update(len(chunk))
        return

    proc = None
    try:
        cmd = [f"./{CORE_NAME}"] if SYSTEM != "Windows" else [CORE_NAME]
        cmd.extend(["run", "-c", cfg_file])
        
        if SYSTEM == "Windows":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(cmd, startupinfo=si, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        ACTIVE_PROCESSES.append(proc)
        
        await asyncio.sleep(2)
        
        if proc.poll() is not None:
            for item in chunk: 
                item['result'] = (False, "Core Died", "XX")
            pbar.update(len(chunk))
            return

        async with aiohttp.ClientSession() as session:
            tasks = []
            for i, item in enumerate(chunk):
                tasks.append(check_proxy_http(session, start_port + i, item, my_ip))
            
            results = await asyncio.gather(*tasks)
            
            for res in results:
                item = res["item"]
                if res["ok"]:
                    item["result"] = (True, f"{res['ping']}ms", res["cc"])
                else:
                    item["result"] = (False, res["msg"], "XX")
                pbar.update(1)

    except (OSError, PermissionError, FileNotFoundError) as e:
        logger.error(f"Subprocess error: {e}")
        for item in chunk: 
            item['result'] = (False, f"Process Error", "XX")
        pbar.update(len(chunk))
    except Exception as e:
        logger.error(f"Batch error: {e}")
    finally:
        if proc:
            try: 
                proc.terminate()
            except (ProcessLookupError, OSError):
                pass
            if proc in ACTIVE_PROCESSES: 
                ACTIVE_PROCESSES.remove(proc)
        
        if os.path.exists(cfg_file):
            try: 
                os.remove(cfg_file)
            except (OSError, FileNotFoundError):
                pass

def print_statistics(parsed_proxies: List[dict], duplicates_count: int):
    """Вывод красивой статистики"""
    if not parsed_proxies: 
        return

    live_counts = Counter()
    total_counts = Counter()
    error_counts = Counter()
    
    total_live = 0
    
    for p in parsed_proxies:
        proto = p['proto']
        total_counts[proto] += 1
        
        res = p['result']
        if res and res[0]: 
            live_counts[proto] += 1
            total_live += 1
        else:
            msg = res[1] if res else "Unknown"
            error_counts[msg] += 1

    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*22} СТАТИСТИКА {'='*22}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Всего загружено: {Fore.WHITE}{len(parsed_proxies) + duplicates_count}")
    print(f"{Fore.RED}Удалено дублей:  {Fore.WHITE}{duplicates_count}")
    print(f"{Fore.CYAN}Проверено (уник): {Fore.WHITE}{len(parsed_proxies)}")
    print(f"{Fore.GREEN}Всего живых:     {Fore.WHITE}{total_live} ({total_live / len(parsed_proxies) * 100:.1f}%)")
    
    print(f"\n{Fore.BLUE}{Style.BRIGHT}{'ПРОТОКОЛ':<15} | {'ЖИВЫЕ':<8} | {'ВСЕГО':<8} | {'УСПЕХ %':<8}{Style.RESET_ALL}")
    print("-" * 50)
    
    for proto in sorted(total_counts.keys()):
        live = live_counts[proto]
        total = total_counts[proto]
        rate = (live / total * 100) if total > 0 else 0
        
        color = Fore.GREEN if rate > 50 else (Fore.YELLOW if rate > 10 else Fore.RED)
        print(f"{proto:<15} | {Fore.GREEN}{live:<8}{Style.RESET_ALL} | {total:<8} | {color}{rate:.1f}%{Style.RESET_ALL}")

    print(f"\n{Fore.RED}{Style.BRIGHT}ТОП ОШИБОК:{Style.RESET_ALL}")
    for err, count in error_counts.most_common(5):
        print(f" - {err:<15}: {count}")
    print("=" * 56)

async def main_async():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}   🚀 PROXY CHECKER v6.5 (Smart Deduplication) | {SYSTEM}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    ensure_core()
    
    my_ip = None
    try:
        print("[*] Определение IP...")
        async with aiohttp.ClientSession() as s:
            async with s.get("http://api.ipify.org?format=json", timeout=5) as r:
                data = await r.json()
                my_ip = data.get("ip")
        print(f"[*] Ваш IP: {Fore.GREEN}{my_ip}{Style.RESET_ALL}")
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError, KeyError):
        print(f"[*] Ваш IP: {Fore.RED}Не определен{Style.RESET_ALL}")

    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    
    raw_keys = []
    if os.path.exists(KEYS_DIR):
        for fn in os.listdir(KEYS_DIR):
            if fn.endswith(".txt"):
                try:
                    with open(os.path.join(KEYS_DIR, fn), "r", encoding="utf-8", errors="ignore") as f:
                        raw_keys.extend([l.strip() for l in f if len(l.strip()) > 10])
                except (IOError, OSError) as e:
                    print(f"Ошибка чтения {fn}: {e}")

    raw_keys = list(set(raw_keys))
    print(f"\n{Fore.BLUE}[*] Загружено строк: {len(raw_keys)}{Style.RESET_ALL}")

    parsed_proxies = []
    unique_fp = set()
    duplicates_count = 0
    
    print("[*] Парсинг конфигов...")
    for link in tqdm(raw_keys, desc="Parsing", ncols=70):
        tag = f"p_{uuid.uuid4().hex[:6]}"
        out, proto, h, p = parse_proxy(link, tag)
        if out:
            # УЛУЧШЕННАЯ ДЕДУПЛИКАЦИЯ: хеш конфигурации без runtime tag
            config_clean = {k: v for k, v in out.items() if k != 'tag'}
            fp = hashlib.md5(json.dumps(config_clean, sort_keys=True).encode()).hexdigest()
            
            if fp not in unique_fp:
                unique_fp.add(fp)
                parsed_proxies.append({
                    'link': link,
                    'tag': tag,
                    'config': out,
                    'proto': proto,
                    'result': None
                })
            else:
                duplicates_count += 1

    print(f"{Fore.CYAN}[✓] Уникальных валидных: {len(parsed_proxies)} (Удалено дублей по конфигурации: {duplicates_count}){Style.RESET_ALL}")
    if not parsed_proxies: 
        return

    chunks = [parsed_proxies[i:i + BATCH_SIZE] for i in range(0, len(parsed_proxies), BATCH_SIZE)]
    
    print(f"\n{Fore.YELLOW}[*] Запуск проверки...{Style.RESET_ALL}")
    
    pbar = tqdm(total=len(parsed_proxies), desc="Checking", ncols=75, colour='green')
    sem = asyncio.Semaphore(2) 
    
    async def limited_batch(c):
        async with sem:
            await run_singbox_batch(c, my_ip, pbar)

    tasks = [limited_batch(chunk) for chunk in chunks]
    await asyncio.gather(*tasks)
    pbar.close()
    
    print_statistics(parsed_proxies, duplicates_count)

    live_res = []
    for p in parsed_proxies:
        if p['result'] and p['result'][0]:
            live_res.append(p)

    if not live_res:
        print(f"\n{Fore.RED}[!] Живых прокси не найдено.{Style.RESET_ALL}")
        return

    live_res.sort(key=lambda x: int(x['result'][1].replace('ms','')))

    out_file = os.path.join(OUT_DIR, "live.txt")
    
    with open(out_file, "w", encoding="utf-8") as f:
        for p in live_res:
            ping = p['result'][1]
            cc = p['result'][2]
            flag = get_flag_emoji(cc)
            raw_name = f"{flag} {cc} | ⚡ {ping} | {p['proto']}"
            
            if p['link'].startswith("vmess://"):
                try:
                    b64_str = p['link'][8:]
                    j = json.loads(robust_base64_decode(b64_str))
                    j['ps'] = raw_name
                    new_json = json.dumps(j, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                    final_link = f"vmess://{base64.b64encode(new_json).decode('utf-8')}"
                except (json.JSONDecodeError, KeyError, TypeError):
                    final_link = f"{clean_url(p['link'])}#{quote(raw_name)}"
            else:
                base_link = clean_url(p['link'])
                final_link = f"{base_link}#{quote(raw_name)}"

            f.write(f"{final_link}\n")

    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"📁 Файл сохранен: {out_file}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
if __name__ == "__main__":
    if SYSTEM == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Остановлено пользователем")
        cleanup_processes()
    except SystemExit:
        cleanup_processes()
        raise
    except Exception as e:
        print(f"\n{Fore.RED}[!] Критическая ошибка: {e}{Style.RESET_ALL}")
        cleanup_processes()
        raise