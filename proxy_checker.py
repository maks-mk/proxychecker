import json
import os
import subprocess
import time
import base64
import requests
import zipfile
import urllib.request
import socket
import statistics
import platform
import tempfile
import random
import uuid
import threading
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from contextlib import contextmanager

# Отключаем предупреждения SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from tqdm import tqdm
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Установите либы: pip install tqdm colorama requests")
    exit(1)

# ================== КОНФИГУРАЦИЯ ==================

KEYS_DIR = "keys"
OUT_DIR = "output"
SYSTEM = platform.system()

# Настройки сети
PING_URL = "https://cp.cloudflare.com/"
GEO_URL = "https://api.myip.com"
TIMEOUT_SEC = 6
CHECK_IP_LEAK = True

# Константы валидации
MIN_KEY_LENGTH = 15
PRE_CHECK_TIMEOUT = 2.0
PORT_RANGE_START = 20000
PORT_RANGE_END = 55000

# Настройки системы
if SYSTEM == "Windows":
    os.system('color')
    CORE_EXE = "sing-box.exe"
    CORE_URL = "https://github.com/SagerNet/sing-box/releases/download/v1.9.0/sing-box-1.9.0-windows-amd64.zip"
    BATCH_SIZE = 8              
    PAUSE_BETWEEN_BATCHES = 1.0 
    STARTUP_TIMEOUT = 25.0      
elif SYSTEM == "Linux":
    CORE_EXE = "sing-box"
    CORE_URL = "https://github.com/SagerNet/sing-box/releases/download/v1.9.0/sing-box-1.9.0-linux-amd64.tar.gz"
    BATCH_SIZE = 50             
    PAUSE_BETWEEN_BATCHES = 0.0 
    STARTUP_TIMEOUT = 8.0       
elif SYSTEM == "Darwin":
    CORE_EXE = "sing-box"
    CORE_URL = "https://github.com/SagerNet/sing-box/releases/download/v1.9.0/sing-box-1.9.0-darwin-amd64.tar.gz"
    BATCH_SIZE = 40             
    PAUSE_BETWEEN_BATCHES = 0.1 
    STARTUP_TIMEOUT = 10.0
else:
    print(f"❌ Неподдерживаемая ОС: {SYSTEM}")
    exit(1)

# === THREADING CONTROL ===
GLOBAL_POOL = ThreadPoolExecutor(max_workers=150) 
TCP_SEM = threading.Semaphore(200)

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
LIVE_FILE = os.path.join(OUT_DIR, "live.txt")

# ================== УТИЛИТЫ ==================

def get_my_ip():
    if not CHECK_IP_LEAK: return None
    print(f"{Fore.YELLOW}[*] Определение вашего IP...{Style.RESET_ALL}", end="")
    try:
        resp = requests.get(GEO_URL, proxies={"http": None, "https": None}, timeout=10).json()
        ip = resp.get("ip")
        print(f" {Fore.GREEN}{ip}{Style.RESET_ALL}")
        return ip
    except Exception as e:
        print(f" {Fore.RED}Ошибка ({e}){Style.RESET_ALL}")
        return None

def get_flag_emoji(cc):
    if not cc or len(cc) != 2 or cc == "XX": return "🏳️"
    try: return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except: return "🏳️"

def robust_base64_decode(s):
    """Улучшенный декодер"""
    if not s: return ""
    s = s.strip().replace(" ", "").replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.b64decode(s).decode('utf-8', errors='ignore')
    except: return ""

def validate_port(p):
    try: return 1 <= int(p) <= 65535
    except: return False

def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def find_free_port_block(size):
    for _ in range(50):
        start = random.randint(PORT_RANGE_START, PORT_RANGE_END - size)
        if all(is_port_free(start + i) for i in range(size)):
            return start
    raise RuntimeError("No free port block available")

def tcp_precheck_task(host, port):
    with TCP_SEM:
        try:
            ip = socket.gethostbyname(host)
            with socket.create_connection((ip, port), timeout=PRE_CHECK_TIMEOUT): return True
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
                if SYSTEM == "Windows":
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    proc.terminate(); proc.wait(timeout=1)
            except: pass

def ensure_core():
    if os.path.exists(CORE_EXE): return
    print(f"[*] Скачивание Sing-box для {SYSTEM}...")
    try:
        urllib.request.urlretrieve(CORE_URL, "singbox_archive")
        if CORE_URL.endswith('.zip'):
            with zipfile.ZipFile("singbox_archive", "r") as z:
                for f in z.namelist():
                    if f.endswith(CORE_EXE) or f.endswith("sing-box.exe"):
                        with open(CORE_EXE, "wb") as fo: fo.write(z.read(f)); break
        else:
            import tarfile
            with tarfile.open("singbox_archive", "r:gz") as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        with open(CORE_EXE, "wb") as fo: fo.write(t.extractfile(m).read()); break
        
        if not os.path.exists(CORE_EXE):
            raise RuntimeError("Core binary not found after extraction!")

        if SYSTEM != "Windows": 
            os.chmod(CORE_EXE, 0o755)
            if SYSTEM == "Darwin":
                try: subprocess.run(["xattr", "-d", "com.apple.quarantine", CORE_EXE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except: pass
        os.remove("singbox_archive")
    except Exception as e:
        if os.path.exists("singbox_archive"): os.remove("singbox_archive")
        print(f"❌ Критическая ошибка скачивания: {e}")
        exit(1)

# ================== НОВЫЙ ПАРСЕР ==================

def parse_proxy(link, tag):
    try:
        link = link.strip()
        if not link: return None, None, False, None, None
        
        outbound = {}
        proto = "Unknown"
        fp = random.choice(["chrome", "firefox", "safari", "edge", "ios"])
        r_host, r_port = None, None

        if link.startswith("vmess://"):
            proto = "VMess"
            j = json.loads(robust_base64_decode(link[8:]))
            r_port = int(j.get("port", 0) or j.get("server_port", 0))
            if not validate_port(r_port): return None, None, False, None, None
            
            r_host = j.get("add") or j.get("host") or j.get("ip")
            outbound = {"type": "vmess", "tag": tag, "server": r_host, "server_port": r_port, "uuid": j.get("id") or j.get("uuid"), "security": "auto"}
            
            net = j.get("net", "tcp")
            if net in ["ws", "websocket"]:
                outbound["transport"] = {"type": "ws", "path": j.get("path", "/"), "headers": {"Host": j.get("host", "")}}
            elif net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": j.get("path", "")}
            
            tls_val = str(j.get("tls", "")).lower()
            if tls_val in ["tls", "1", "true"]:
                outbound["tls"] = {"enabled": True, "server_name": j.get("sni") or j.get("host") or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}

        elif link.startswith("vless://"):
            proto = "VLESS"
            u = urlparse(link); q = parse_qs(u.query)
            if not validate_port(str(u.port)): return None, None, False, None, None
            r_host, r_port = u.hostname, u.port
            outbound = {"type": "vless", "tag": tag, "server": r_host, "server_port": r_port, "uuid": u.username, "flow": q.get("flow", [""])[0]}
            
            type_net = q.get("type", ["tcp"])[0]
            if type_net == "ws": outbound["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [""])[0]}}
            elif type_net == "grpc": outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}
            
            security = q.get("security", ["none"])[0]
            if security == "tls":
                outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}
            elif security == "reality":
                outbound["tls"] = {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "reality": {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}, "utls": {"enabled": True, "fingerprint": q.get("fp", [fp])[0]}}

        elif link.startswith("ss://"):
            proto = "Shadowsocks"
            parsed = urlparse(link)
            if not parsed.netloc: # Old format
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
            if not u.port or not validate_port(str(u.port)): return None, None, False, None, None
            r_host, r_port = u.hostname, u.port
            outbound = {"type": "trojan", "tag": tag, "server": r_host, "server_port": r_port, "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [""])[0] or r_host, "insecure": True, "utls": {"enabled": True, "fingerprint": fp}}}

        elif link.startswith(("hy2://", "hysteria2://")):
            proto = "Hysteria2"
            u = urlparse(link); q = parse_qs(u.query)
            if not u.port or not validate_port(str(u.port)): return None, None, False, None, None
            pwd = unquote(u.password or u.username or "")
            r_host, r_port = u.hostname, u.port
            outbound = {"type": "hysteria2", "tag": tag, "server": r_host, "server_port": r_port, "password": pwd,
                "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "insecure": True, "alpn": ["h3"]}}
            if q.get("obfs-password"): outbound["obfs"] = {"type": "salamander", "password": q.get("obfs-password")[0]}

        if not outbound: return None, None, False, None, None
        return outbound, proto, r_host, r_port
    except: return None, None, False, None, None

# ================== ГЕНЕРАТОР КОНФИГА ==================

def generate_multi_port_config(proxies_chunk, start_port):
    inbounds = []
    outbounds = []
    rules = []
    
    for i, item in enumerate(proxies_chunk):
        local_port = start_port + i
        proxy_tag = item['tag']
        inbound_tag = f"in_{local_port}"
        
        outbounds.append(item['config'])
        inbounds.append({
            "type": "mixed", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": local_port, "sniff": False
        })
        rules.append({"inbound": inbound_tag, "outbound": proxy_tag})

    outbounds.extend([{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}, {"type": "dns", "tag": "dns-out"}])
    config = {"log": {"level": "fatal"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules, "auto_detect_interface": True}}
    return config

# ================== ПРОВЕРКА ==================

def wait_for_ports(start_port, count, timeout):
    check_limit = min(count, 5)
    ports_to_check = [start_port + i for i in range(check_limit)]
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready_count = 0
        for port in ports_to_check:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1): ready_count += 1
            except: pass
        if ready_count == len(ports_to_check): return True
        time.sleep(0.15)
    return False

def check_one_http(args):
    idx, item, sp, verify_ssl, local_ip = args
    port = sp + idx
    proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
    try:
        t_start = time.time()
        resp = requests.get(PING_URL, proxies=proxies, timeout=TIMEOUT_SEC, verify=verify_ssl, allow_redirects=False)
        lat = int((time.time() - t_start) * 1000)
        
        if resp.status_code == 204 or (resp.status_code == 200 and len(resp.content) < 1000):
            try:
                geo_resp = requests.get(GEO_URL, proxies=proxies, timeout=5, verify=False).json()
                remote_ip = geo_resp.get("ip")
                country = geo_resp.get("cc", "XX")
                if CHECK_IP_LEAK and local_ip and remote_ip == local_ip: return (False, "IP Leak", None, item)
                return (True, f"{lat}ms", country, item)
            except: return (True, f"{lat}ms", "XX", item)
        else: return (False, "Bad Status", None, item)
            
    except requests.exceptions.SSLError: return (False, "SSL Error", None, item)
    except requests.exceptions.Timeout: return (False, "Timeout", None, item)
    except requests.exceptions.ConnectionError: return (False, "Conn Err", None, item)
    except: return (False, "Sys Err", None, item)

def process_batch(chunk, pbar, local_ip):
    try:
        current_start_port = find_free_port_block(len(chunk))
    except RuntimeError:
        for item in chunk: item['result'] = (False, "No Ports")
        pbar.update(len(chunk))
        return
    
    config = generate_multi_port_config(chunk, current_start_port)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        cfg_filename = tmp.name
        json.dump(config, tmp)
    
    try:
        with managed_process([CORE_EXE, "run", "-c", cfg_filename]) as proc:
            if not wait_for_ports(current_start_port, len(chunk), STARTUP_TIMEOUT):
                msg = "Core Fail" if proc.poll() is not None else "Bind Timeout"
                for item in chunk: item['result'] = (False, msg)
                pbar.update(len(chunk))
                return
            
            time.sleep(0.5)
            
            args_list = []
            for i, item in enumerate(chunk):
                port = current_start_port + i
                proto = item['proto']
                is_reality = item.get('is_reality', False)
                verify_ssl = not (proto == "Hysteria2" or is_reality) # H2 self-signed often
                args_list.append((i, item, current_start_port, False, local_ip)) # verify=False globally for checker

            futures = {GLOBAL_POOL.submit(check_one_http, arg): arg[1] for arg in args_list}
            
            for future in as_completed(futures):
                item = futures[future]
                try:
                    is_live, msg, country, _ = future.result()
                    if is_live: item['result'] = (True, msg, country)
                    else: item['result'] = (False, msg)
                except: item['result'] = (False, "Sys Err")
                pbar.update(1)

    except Exception as e:
        for item in chunk: 
            if item['result'] is None: item['result'] = (False, "Batch Err")
        pbar.update(len(chunk))
    finally:
        try: os.remove(cfg_filename)
        except: pass
        time.sleep(PAUSE_BETWEEN_BATCHES)

# ================== MAIN ==================

def main():
    start_time = time.time()
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}   🚀 PROXY CHECKER v5.1 (Improved) | {SYSTEM}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    ensure_core()
    my_real_ip = get_my_ip()
    
    raw_keys = []
    if os.path.exists(KEYS_DIR):
        for fn in os.listdir(KEYS_DIR):
            if fn.endswith(".txt"):
                with open(os.path.join(KEYS_DIR, fn), "r", encoding="utf-8", errors="ignore") as f:
                    raw_keys.extend([l.strip() for l in f if len(l.strip()) >= MIN_KEY_LENGTH and not l.startswith("#")])
    
    raw_keys = list(set(raw_keys))
    print(f"\n{Fore.BLUE}[*] Ключей найдено: {len(raw_keys)}{Style.RESET_ALL}")
    
    parsed_proxies = []
    print(f"[*] Парсинг ссылок...")
    for link in tqdm(raw_keys, desc="Parsing", ncols=80):
        tag = f"p_{uuid.uuid4().hex[:8]}"
        outbound, proto, r_host, r_port = parse_proxy(link, tag)
        if outbound: 
            parsed_proxies.append({'link': link, 'tag': tag, 'config': outbound, 'proto': proto, 'host': r_host, 'port': r_port, 'result': None})
    
    print(f"{Fore.CYAN}[✓] Распарсено валидных: {len(parsed_proxies)}/{len(raw_keys)}{Style.RESET_ALL}")
    if not parsed_proxies: return

    print(f"\n{Fore.YELLOW}[*] Предварительный TCP Check (отсев мертвых)...{Style.RESET_ALL}")
    alive_proxies = []
    futures = {GLOBAL_POOL.submit(tcp_precheck_task, item['host'], item['port']): item for item in parsed_proxies}
    
    for future in tqdm(as_completed(futures), total=len(parsed_proxies), desc="TCP Check", ncols=80, colour='yellow'):
        item = futures[future]
        if future.result(): alive_proxies.append(item)
    
    print(f"{Fore.GREEN}[✓] Прошло TCP Check: {len(alive_proxies)} (Отсеяно: {len(parsed_proxies) - len(alive_proxies)}){Style.RESET_ALL}")
    if not alive_proxies: return

    chunks = [alive_proxies[i:i + BATCH_SIZE] for i in range(0, len(alive_proxies), BATCH_SIZE)]
    print(f"\n{Fore.CYAN}[*] Запуск Full Check (Батчей: {len(chunks)})...{Style.RESET_ALL}\n")
    
    stats_proto = Counter()
    stats_errors = Counter()
    live_results = []
    all_pings = []
    
    with tqdm(total=len(alive_proxies), desc="Checking", ncols=80, colour='green') as pbar:
        for chunk in chunks:
            process_batch(chunk, pbar, my_real_ip)
            for item in chunk:
                proto = item['proto']
                stats_proto[proto] += 1
                res = item['result']
                is_live = res[0]
                msg = res[1]
                
                if is_live:
                    country = res[2] if len(res) > 2 else "XX"
                    ping = int(msg.replace("ms", ""))
                    live_results.append((ping, item['link'], proto, country))
                    all_pings.append(ping)
                else: stats_errors[msg] += 1
    
    live_results.sort(key=lambda x: x[0])
    with open(LIVE_FILE, "w", encoding="utf-8") as f:
        for ping, link, proto, country in live_results:
            flag = get_flag_emoji(country)
            clean_link = link.split('#')[0]
            name = f"{flag} {country} | 🚀 {ping}ms | {proto}"
            f.write(f"{clean_link}#{name}\n")
    
    print("\n" + "="*60)
    print(f"⏱  Время: {time.time()-start_time:.2f} сек")
    print("-" * 60)
    print(f"✅ {Fore.GREEN}ЖИВЫХ (HTTPS): {len(live_results)}{Style.RESET_ALL}")
    
    total_dead = len(parsed_proxies) - len(live_results)
    print(f"❌ {Fore.RED}МЕРТВЫХ:       {total_dead}{Style.RESET_ALL}")
    
    if all_pings:
        print("-" * 60)
        print(f"🚀 {Style.BRIGHT}PING:{Style.RESET_ALL} Avg: {Fore.YELLOW}{int(statistics.mean(all_pings))}ms{Style.RESET_ALL} | Best: {Fore.GREEN}{min(all_pings)}ms{Style.RESET_ALL}")
    
    print("-" * 60)
    print("📂 ПРОТОКОЛЫ:")
    for proto, count in stats_proto.most_common():
        print(f"   • {proto:<15} : {count}")

    if stats_errors:
        print("-" * 60)
        print("❌ ПРИЧИНЫ ОШИБОК:")
        tcp_dead = len(parsed_proxies) - len(alive_proxies)
        if tcp_dead > 0:
            print(f"   • {'TCP/Port Closed':<15} : {Fore.RED}{tcp_dead}{Style.RESET_ALL}")
        for err, count in stats_errors.most_common(): 
            print(f"   • {err:<15} : {Fore.RED}{count}{Style.RESET_ALL}")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Прервано{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n❌ Произошла ошибка: {e}")
    finally:
        print("\n" + "="*60)
        input("Нажмите Enter, чтобы закрыть программу...")