import json
import os
import subprocess
import time
import base64
import requests
import zipfile
import urllib.request
import platform
import socket
import uuid
import random
import tempfile
import binascii
from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import urllib3

urllib3.disable_warnings()

# === SETTINGS (OPTIMIZED FOR WEAK VPS/PC) ===
SYSTEM = platform.system()
PING_URL = "https://cp.cloudflare.com/"
GEO_URL = "https://api.myip.com"
TIMEOUT_SEC = 8  # Чуть больше времени на ответ
CHECK_IP_LEAK = True 

# Настройки процесса
# Даем больше времени на запуск ядра, так как батчи будут большими
STARTUP_TIMEOUT = 25.0 
PAUSE_BETWEEN_BATCHES = 0.5

SING_VER = "1.11.4"

if SYSTEM == "Windows":
    CORE_NAME = "sing-box.exe"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-windows-amd64.zip"
elif SYSTEM == "Linux":
    CORE_NAME = "sing-box"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-linux-amd64.tar.gz"
elif SYSTEM == "Darwin":
    CORE_NAME = "sing-box"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-darwin-amd64.tar.gz"
else: 
    print(f"Unsupported OS: {SYSTEM}")
    exit(1)

# Ограничиваем потоки, чтобы CPU не захлебнулся (было 200)
GLOBAL_POOL = ThreadPoolExecutor(max_workers=60)

# === UTILS ===

def get_my_ip():
    if not CHECK_IP_LEAK: return None
    try: return requests.get(GEO_URL, proxies={"http": None, "https": None}, timeout=5).json().get("ip")
    except: return None

def robust_base64_decode(s):
    if not s: return ""
    s = s.strip().replace(" ", "").replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def validate_port(p):
    try: return 1 <= int(p) <= 65535
    except: return False

def clean_url_logic(link):
    """Очистка ссылки от мусора для лучшей дедупликации"""
    try:
        link = link.strip()
        if '#' in link: link = link.split('#')[0]
        if "://" in link:
            u = urlparse(link)
            if u.query:
                q = parse_qs(u.query, keep_blank_values=True)
                changed = False
                for junk in ['name', 'spider', 'remarks', 'plugin', 'udp', 'allowInsecure']:
                    if junk in q: del q[junk]; changed = True
                if changed:
                    new_query = urlencode(q, doseq=True)
                    link = urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, ''))
        return link
    except: return link

def tcp_precheck_task(host, port):
    try:
        with socket.create_connection((host, port), timeout=2.5): return True
    except: return False

@contextmanager
def managed_process(cmd):
    proc = None
    try:
        if SYSTEM == "Windows":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, startupinfo=si, creationflags=0x08000000)
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        yield proc
    finally:
        if proc:
            try:
                if SYSTEM == "Windows": subprocess.call(['taskkill', '/F', '/T', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else: proc.terminate(); proc.wait(timeout=1)
            except: pass

def ensure_core():
    if os.path.exists(CORE_NAME): return
    print(f"[*] Downloading {CORE_NAME} v{SING_VER}...")
    try:
        urllib.request.urlretrieve(CORE_URL, "singbox_archive")
        if CORE_URL.endswith('.zip'):
            with zipfile.ZipFile("singbox_archive", "r") as z:
                for f in z.namelist():
                    if f.endswith(CORE_NAME) or f.endswith("sing-box.exe"):
                        with open(CORE_NAME, "wb") as fo: fo.write(z.read(f)); break
        else:
            import tarfile
            with tarfile.open("singbox_archive", "r:gz") as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        with open(CORE_NAME, "wb") as fo: fo.write(t.extractfile(m).read()); break
        
        if SYSTEM != "Windows": 
            os.chmod(CORE_NAME, 0o755)
            if SYSTEM == "Darwin":
                try: subprocess.run(["xattr", "-d", "com.apple.quarantine", CORE_NAME], stderr=subprocess.DEVNULL)
                except: pass
        
        if os.path.exists("singbox_archive"): os.remove("singbox_archive")
        
    except Exception as e:
        if os.path.exists("singbox_archive"): os.remove("singbox_archive")
        if os.path.exists(CORE_NAME): os.remove(CORE_NAME)
        raise RuntimeError(f"Failed to download sing-box core: {e}")

# === PARSER ===

def parse_proxy(link, tag):
    try:
        link = link.strip()
        if not link: return None, None, None, None
        
        outbound = {}
        proto = "Unknown"
        fp = "chrome" 
        r_host, r_port = None, None

        if link.startswith("vmess://"):
            proto = "VMess"
            j = json.loads(robust_base64_decode(link[8:]))
            r_port = int(j.get("port", 0) or j.get("server_port", 0))
            if not validate_port(r_port): return None, None, None, None
            
            r_host = j.get("add") or j.get("host") or j.get("ip")
            outbound = {"type": "vmess", "tag": tag, "server": r_host, "server_port": r_port, "uuid": j.get("id") or j.get("uuid"), "security": "auto"}
            
            net = j.get("net", "tcp")
            if net in ["ws", "websocket"]:
                outbound["transport"] = {"type": "ws", "path": j.get("path", "/"), "headers": {"Host": j.get("host", "")}}
            elif net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": j.get("path", "")}
            
            if str(j.get("tls", "")).lower() in ["tls", "1", "true"]:
                outbound["tls"] = {"enabled": True, "server_name": j.get("sni") or j.get("host") or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}

        elif link.startswith("vless://"):
            proto = "VLESS"
            u = urlparse(link); q = parse_qs(u.query)
            if not validate_port(str(u.port)): return None, None, None, None
            r_host, r_port = u.hostname, u.port
            outbound = {"type": "vless", "tag": tag, "server": r_host, "server_port": r_port, "uuid": u.username, "flow": q.get("flow", [""])[0]}
            
            type_net = q.get("type", ["tcp"])[0]
            if type_net == "ws": outbound["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [""])[0]}}
            elif type_net == "grpc": outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}
            
            sec = q.get("security", ["none"])[0]
            if sec == "tls":
                outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}
            elif sec == "reality":
                outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "reality": {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}, "utls": {"enabled": True, "fingerprint": q.get("fp", [fp])[0]}}

        elif link.startswith("ss://"):
            proto = "Shadowsocks"
            parsed = urlparse(link)
            if not parsed.netloc:
                parts = link[5:].split('#', 1)
                decoded = robust_base64_decode(parts[0])
                if '@' in decoded: parsed = urlparse(f"ss://{decoded}")
            
            if parsed.netloc and '@' in parsed.netloc:
                userinfo, host_port = parsed.netloc.rsplit('@', 1)
                if ':' in host_port:
                    r_host, p_str = host_port.rsplit(':', 1)
                    p_str = p_str.split('/')[0].split('?')[0]
                    if validate_port(p_str):
                        r_port = int(p_str)
                        if ':' not in userinfo: userinfo = robust_base64_decode(userinfo)
                        if ':' in userinfo:
                            method, pwd = userinfo.split(':', 1)
                            outbound = {"type": "shadowsocks", "tag": tag, "server": r_host, "server_port": r_port, "method": method, "password": unquote(pwd)}

        elif link.startswith("trojan://"):
            proto = "Trojan"
            u = urlparse(link); q = parse_qs(u.query)
            if not u.port or not validate_port(str(u.port)): return None, None, None, None
            r_host, r_port = u.hostname, u.port
            outbound = {"type": "trojan", "tag": tag, "server": r_host, "server_port": r_port, "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}}

        elif link.startswith(("hy2://", "hysteria2://")):
            proto = "Hysteria2"
            u = urlparse(link); q = parse_qs(u.query)
            if not u.port or not validate_port(str(u.port)): return None, None, None, None
            pwd = unquote(u.password or u.username or "")
            r_host, r_port = u.hostname, u.port
            sni = q.get("sni", [u.hostname])[0]
            outbound = {"type": "hysteria2", "tag": tag, "server": r_host, "server_port": r_port, "password": pwd,
                "tls": {"enabled": True, "server_name": sni, "insecure": True, "alpn": ["h3"]}}
            if q.get("obfs-password"): outbound["obfs"] = {"type": "salamander", "password": q.get("obfs-password")[0]}

        if not outbound: return None, None, None, None
        return outbound, proto, r_host, r_port
    except Exception as e:
        return None, None, None, None

# === BATCH CHECK ===

def wait_for_ports(start, count):
    # Увеличиваем время ожидания старта ядра
    deadline = time.time() + STARTUP_TIMEOUT
    ports = [start + i for i in range(min(count, 5))]
    while time.time() < deadline:
        ready = 0
        for p in ports:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.1): ready += 1
            except: pass
        if ready == len(ports): return True
        time.sleep(0.2)
    return False

def check_one_http_task(args):
    idx, item, sp, local_ip = args
    proxies = {'http': f'http://127.0.0.1:{sp+idx}', 'https': f'http://127.0.0.1:{sp+idx}'}
    try:
        t0 = time.time()
        # allow_redirects=False для скорости
        r = requests.get(PING_URL, proxies=proxies, timeout=TIMEOUT_SEC, verify=False, allow_redirects=False)
        lat = int((time.time() - t0) * 1000)
        
        if r.status_code == 204 or (r.status_code == 200 and len(r.content) < 1000):
            try:
                geo = requests.get(GEO_URL, proxies=proxies, timeout=4, verify=False).json()
                if CHECK_IP_LEAK and local_ip and geo.get("ip") == local_ip: return (False, 0, "LEAK", item)
                return (True, lat, geo.get("cc", "XX"), item)
            except: return (True, lat, "XX", item)
    except requests.exceptions.Timeout: return (False, 0, "Timeout", item)
    except: pass
    return (False, 0, "Fail", item)

def check_batch_sync(chunk, sp, local_ip):
    inbounds = [{"type": "mixed", "tag": f"in_{sp+i}", "listen": "127.0.0.1", "listen_port": sp+i, "sniff": False} for i in range(len(chunk))]
    outbounds = [i['config'] for i in chunk] + [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns-out"}]
    rules = [{"inbound": f"in_{sp+i}", "outbound": chunk[i]['tag']} for i in range(len(chunk))]
    
    cfg = {"log": {"level": "fatal"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules, "auto_detect_interface": True}}
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(cfg, tmp); tmp_name = tmp.name
    
    try:
        with managed_process([os.path.abspath(CORE_NAME), "run", "-c", tmp_name]) as proc:
            if not wait_for_ports(sp, len(chunk)):
                raise RuntimeError("Bind Timeout")

            time.sleep(0.5)
            args_list = [(i, item, sp, local_ip) for i, item in enumerate(chunk)]
            return list(GLOBAL_POOL.map(check_one_http_task, args_list))
    except RuntimeError:
        return [(False, 0, "Core Bind Fail", item) for item in chunk]
    finally:
        try: os.remove(tmp_name)
        except: pass
        if PAUSE_BETWEEN_BATCHES > 0: time.sleep(PAUSE_BETWEEN_BATCHES)