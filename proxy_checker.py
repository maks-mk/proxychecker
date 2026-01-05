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
from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from contextlib import contextmanager

# Отключаем SSL предупреждения
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from tqdm import tqdm
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Установите либы: pip install tqdm colorama requests")
    exit(1)

# ================== КОНФИГУРАЦИЯ (LITE / DETAILED STATS) ==================

KEYS_DIR = "keys"
OUT_DIR = "output"
SYSTEM = platform.system()

PING_URL = "https://cp.cloudflare.com/"
GEO_URL = "https://api.myip.com"
TIMEOUT_SEC = 8         
CHECK_IP_LEAK = True

# Настройки производительности (под слабый ПК)
if SYSTEM == "Windows":
    BATCH_SIZE = 100            
    STARTUP_TIMEOUT = 35.0      
    PAUSE_BETWEEN_BATCHES = 1.0 
else:
    BATCH_SIZE = 100
    STARTUP_TIMEOUT = 15.0
    PAUSE_BETWEEN_BATCHES = 0.5

SING_VER = "1.11.4"
# Авто-выбор имени файла
if SYSTEM == "Windows":
    os.system('color')
    CORE_EXE = "sing-box.exe"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-windows-amd64.zip"
elif SYSTEM == "Linux":
    CORE_EXE = "sing-box"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-linux-amd64.tar.gz"
elif SYSTEM == "Darwin":
    CORE_EXE = "sing-box"
    CORE_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-darwin-amd64.tar.gz"
else:
    exit(1)

GLOBAL_POOL = ThreadPoolExecutor(max_workers=60) 
TCP_SEM = threading.Semaphore(150)

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
LIVE_FILE = os.path.join(OUT_DIR, "live.txt")

# ================== ФУНКЦИИ ==================

def get_flag_emoji(cc):
    if not cc or len(cc) != 2 or cc == "XX": return "🏳️"
    try: return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except: return "🏳️"

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

def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0

def find_free_port_block(size):
    for _ in range(50):
        start = random.randint(20000, 55000)
        if is_port_free(start) and is_port_free(start + size - 1):
            return start
    raise RuntimeError("Нет свободных портов")

def tcp_precheck_task(host, port):
    with TCP_SEM:
        try:
            with socket.create_connection((host, port), timeout=2.5): return True
        except: return False

def clean_url_logic(link):
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
    if os.path.exists(CORE_EXE): return
    print(f"[*] Скачивание Sing-box v{SING_VER}...")
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
        
        if SYSTEM != "Windows": os.chmod(CORE_EXE, 0o755)
        os.remove("singbox_archive")
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        exit(1)

# ================== ПАРСЕР ==================

def parse_proxy(link, tag):
    try:
        link = link.strip()
        if not link: return None, None, False, None, None
        
        outbound = {}
        proto = "Unknown"
        fp = "chrome" 
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
            
            if str(j.get("tls", "")).lower() in ["tls", "1", "true"]:
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
            sni = q.get("sni", [u.hostname])[0]
            outbound = {"type": "hysteria2", "tag": tag, "server": r_host, "server_port": r_port, "password": pwd,
                "tls": {"enabled": True, "server_name": sni, "insecure": True, "alpn": ["h3"]}}
            if q.get("obfs-password"): outbound["obfs"] = {"type": "salamander", "password": q.get("obfs-password")[0]}

        if not outbound: return None, None, False, None, None
        return outbound, proto, r_host, r_port
    except: return None, None, False, None, None

# ================== CHECK CORE ==================

def wait_for_ports(start_port, count, timeout):
    deadline = time.time() + timeout
    ports_to_check = [start_port + i for i in range(min(count, 3))]
    while time.time() < deadline:
        ready = 0
        for p in ports_to_check:
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.1): ready += 1
            except: pass
        if ready == len(ports_to_check): return True
        time.sleep(0.1)
    return False

def check_one_http(args):
    idx, item, sp, local_ip = args
    port = sp + idx
    proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
    try:
        t_start = time.time()
        resp = requests.get(PING_URL, proxies=proxies, timeout=TIMEOUT_SEC, verify=False, allow_redirects=False)
        lat = int((time.time() - t_start) * 1000)
        
        if resp.status_code == 204 or (resp.status_code == 200 and len(resp.content) < 1000):
            try:
                geo_resp = requests.get(GEO_URL, proxies=proxies, timeout=3, verify=False).json()
                remote_ip = geo_resp.get("ip")
                country = geo_resp.get("cc", "XX")
                if CHECK_IP_LEAK and local_ip and remote_ip == local_ip: return (False, "IP Leak", None, item)
                return (True, f"{lat}ms", country, item)
            except: return (True, f"{lat}ms", "XX", item)
        else: return (False, "Bad Status", None, item)
    except requests.exceptions.Timeout: return (False, "Timeout", None, item)
    except requests.exceptions.SSLError: return (False, "SSL Error", None, item)
    except: return (False, "Conn Error", None, item)

def process_batch(chunk, pbar, local_ip):
    try:
        sp = find_free_port_block(len(chunk))
    except:
        for item in chunk: item['result'] = (False, "No Ports")
        pbar.update(len(chunk))
        return
    
    inbounds = [{"type": "mixed", "tag": f"in_{sp+i}", "listen": "127.0.0.1", "listen_port": sp+i, "sniff": False} for i in range(len(chunk))]
    outbounds = [i['config'] for i in chunk] + [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns-out"}]
    rules = [{"inbound": f"in_{sp+i}", "outbound": chunk[i]['tag']} for i in range(len(chunk))]
    config = {"log": {"level": "fatal"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules}}
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(config, tmp); cfg_file = tmp.name
    
    try:
        with managed_process([CORE_EXE, "run", "-c", cfg_file]) as proc:
            if not wait_for_ports(sp, len(chunk), STARTUP_TIMEOUT):
                for item in chunk: item['result'] = (False, "Bind Fail")
                pbar.update(len(chunk))
                return
            
            time.sleep(0.5)
            
            args = [(i, item, sp, local_ip) for i, item in enumerate(chunk)]
            futures = {GLOBAL_POOL.submit(check_one_http, a): a[1] for a in args}
            
            for future in as_completed(futures):
                item = futures[future]
                try:
                    ok, msg, cc, _ = future.result()
                    item['result'] = (ok, msg, cc) if ok else (False, msg)
                except: item['result'] = (False, "Err")
                pbar.update(1)
    finally:
        try: os.remove(cfg_file)
        except: pass
        if PAUSE_BETWEEN_BATCHES > 0: time.sleep(PAUSE_BETWEEN_BATCHES)

def print_final_stats(total_processed, live_results, error_counts, start_time):
    duration = time.time() - start_time
    speed = total_processed / duration if duration > 0 else 0
    success_rate = (len(live_results) / total_processed * 100) if total_processed > 0 else 0
    
    # Ping Stats
    all_pings = [x[0] for x in live_results]
    if all_pings:
        avg_ping = int(statistics.mean(all_pings))
        median_ping = int(statistics.median(all_pings))
        min_ping = min(all_pings)
        max_ping = max(all_pings)
        fast_proxies = len([p for p in all_pings if p < 500])
    else:
        avg_ping = median_ping = min_ping = max_ping = fast_proxies = 0

    # Country Stats
    countries = Counter([x[3] for x in live_results])
    
    # Protocol Stats
    protocols = Counter([x[2] for x in live_results])

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT}   📊 РАСШИРЕННАЯ СТАТИСТИКА")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    print(f"⏱  Время: {Fore.YELLOW}{duration:.1f}s{Style.RESET_ALL} | Скорость: {Fore.YELLOW}{speed:.1f} prx/s{Style.RESET_ALL}")
    print(f"✅ Результат: {Fore.GREEN}{len(live_results)}{Style.RESET_ALL}/{total_processed} ({Fore.MAGENTA}{success_rate:.1f}%{Style.RESET_ALL})")
    
    if all_pings:
        print(f"\n🚀 {Style.BRIGHT}ПИНГ И СКОРОСТЬ:{Style.RESET_ALL}")
        print(f"   • Мин: {Fore.GREEN}{min_ping}ms{Style.RESET_ALL} | Макс: {Fore.RED}{max_ping}ms{Style.RESET_ALL}")
        print(f"   • Средний: {Fore.YELLOW}{avg_ping}ms{Style.RESET_ALL} | Медиана: {Fore.CYAN}{median_ping}ms{Style.RESET_ALL}")
        print(f"   • Быстрых (<500ms): {Fore.GREEN}{fast_proxies}{Style.RESET_ALL} ({int(fast_proxies/len(live_results)*100)}%)")

    if countries:
        print(f"\n🌍 {Style.BRIGHT}ТОП-10 СТРАН:{Style.RESET_ALL}")
        for cc, count in countries.most_common(10):
            print(f"   {get_flag_emoji(cc)} {cc:<4}: {count}")

    if protocols:
        print(f"\n📂 {Style.BRIGHT}ПРОТОКОЛЫ:{Style.RESET_ALL}")
        for proto, count in protocols.most_common():
            print(f"   • {proto:<15}: {count}")

    if error_counts:
        print(f"\n❌ {Style.BRIGHT}АНАЛИЗ ОШИБОК (ТОП):{Style.RESET_ALL}")
        for err, count in error_counts.most_common(5):
             print(f"   • {err:<15}: {Fore.RED}{count}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

# ================== MAIN ==================

def main():
    start_time_all = time.time()
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}   🚀 PROXY CHECKER v5.7 (STATS+) | {SYSTEM}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    ensure_core()
    
    try:
        my_ip = requests.get(GEO_URL, timeout=8).json().get("ip")
        print(f"[*] Ваш IP: {Fore.GREEN}{my_ip}{Style.RESET_ALL}")
    except: my_ip = None
    
    raw_keys = []
    if os.path.exists(KEYS_DIR):
        for fn in os.listdir(KEYS_DIR):
            if fn.endswith(".txt"):
                try:
                    with open(os.path.join(KEYS_DIR, fn), "r", encoding="utf-8", errors="ignore") as f:
                        raw_keys.extend([l.strip() for l in f if len(l.strip()) >= 15])
                except: pass
    
    raw_keys = list(set(raw_keys))
    print(f"\n{Fore.BLUE}[*] Загружено строк: {len(raw_keys)}{Style.RESET_ALL}")
    
    parsed_proxies = []
    unique_fp = set()
    
    print(f"[*] Парсинг и дедупликация (Smart Mode)...")
    for link in tqdm(raw_keys, desc="Parsing", ncols=80):
        try:
            cl = clean_url_logic(link)
            tag = f"p_{uuid.uuid4().hex[:8]}"
            out, proto, h, p = parse_proxy(cl, tag)
            
            if out and h and p:
                auth = str(out.get("uuid", out.get("password", "")))
                key = f"{h}:{p}:{proto}:{auth}"
                
                if key not in unique_fp:
                    unique_fp.add(key)
                    parsed_proxies.append({'link': cl, 'tag': tag, 'config': out, 'proto': proto, 'host': h, 'port': p, 'result': None})
        except: continue
    
    print(f"{Fore.CYAN}[✓] Уникальных конфигов: {len(parsed_proxies)} (из {len(raw_keys)}){Style.RESET_ALL}")
    if not parsed_proxies: return

    print(f"\n{Fore.YELLOW}[*] TCP Check (отсев мертвых портов)...{Style.RESET_ALL}")
    alive = []
    futures = {GLOBAL_POOL.submit(tcp_precheck_task, i['host'], i['port']): i for i in parsed_proxies}
    
    for f in tqdm(as_completed(futures), total=len(parsed_proxies), desc="TCP Check", ncols=80, colour='yellow'):
        if f.result(): alive.append(futures[f])
    
    tcp_closed_count = len(parsed_proxies) - len(alive)
    print(f"{Fore.GREEN}[✓] Живых TCP: {len(alive)}{Style.RESET_ALL}")
    if not alive: return

    print(f"\n{Fore.CYAN}[*] Full Check ({len(alive)})...{Style.RESET_ALL}")
    chunks = [alive[i:i + BATCH_SIZE] for i in range(0, len(alive), BATCH_SIZE)]
    
    live_res = []
    stats_errors = Counter()
    
    # Добавляем ошибки TCP Check в общую статистику
    if tcp_closed_count > 0:
        stats_errors['TCP Closed'] += tcp_closed_count
    
    with tqdm(total=len(alive), desc="Checking", ncols=80, colour='green') as pbar:
        for chunk in chunks:
            process_batch(chunk, pbar, my_ip)
            for item in chunk:
                res = item['result']
                if res and res[0]:
                    ping = int(res[1].replace("ms", ""))
                    live_res.append((ping, item['link'], item['proto'], res[2]))
                else:
                    msg = res[1] if res else "Unknown"
                    stats_errors[msg] += 1
    
    live_res.sort(key=lambda x: x[0])
    
    with open(LIVE_FILE, "w", encoding="utf-8") as f:
        for ping, link, proto, cc in live_res:
            name = f"{get_flag_emoji(cc)} {cc} | 🚀 {ping}ms | {proto}"
            f.write(f"{link}#{name}\n")
    
    # ВЫЗОВ НОВОЙ ФУНКЦИИ СТАТИСТИКИ
    print_final_stats(len(parsed_proxies), live_res, stats_errors, start_time_all)
    input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()