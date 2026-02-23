import asyncio
import atexit
import base64
import hashlib
import json
import logging
import os
import platform
import random
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
import argparse
from typing import Optional, Tuple, List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote, quote

# ================== НАСТРОЙКИ ЛОГИРОВАНИЯ ==================
LOG_FILE = "checker_debug.log"

# Настройка логгера
logger = logging.getLogger("ProxyChecker")
logger.setLevel(logging.DEBUG)

# Форматтер
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Файловый хендлер (пишет все подробности в файл)
file_handler = logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Консольный хендлер (выводит только ошибки, чтобы не засорять экран)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
console_handler.setFormatter(formatter)

# Добавляем хендлеры
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ================== ПРОВЕРКА БИБЛИОТЕК ==================
try:
    import aiohttp
    from tqdm import tqdm
    from colorama import init, Fore, Style
    import urllib3
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    init(autoreset=True)
except ImportError as e:
    print(f"❌ Ошибка: Не установлены необходимые библиотеки. ({e})")
    print("👉 Выполните: pip install aiohttp tqdm colorama")
    sys.exit(1)

# ================== КОНФИГУРАЦИЯ ==================

KEYS_DIR = "keys"
OUT_DIR = "output"
SYSTEM = platform.system()

PING_URL = "https://cp.cloudflare.com/"
GEO_URL = "http://ip-api.com/json/"
SPEED_TEST_URL = "http://speed.cloudflare.com/__down?bytes=10485760"  # 10 MB

# Тайм-ауты
TIMEOUT_SEC = 8
SPEED_TIMEOUT_SEC = 25

# Размер пачки (снижен для стабильности на Windows)
BATCH_SIZE = 40 if SYSTEM == "Windows" else 80

# Фильтры
MAX_PING = 800       # Отсеивание по пингу (можно переопределить через аргументы)
TOP_PERCENT = 0.50    # Проверять скорость у топ 50% по пингу
MIN_SPEED = 5.0       # Минимальная скорость в Mbps (можно переопределить через аргументы)

# ================== ПАРСИНГ АРГУМЕНТОВ ==================
def parse_args():
    parser = argparse.ArgumentParser(description="Proxy Checker v6.8.3")
    parser.add_argument("-p", "--ping", type=int, default=MAX_PING, help=f"Максимальный пинг (по умолчанию: {MAX_PING} мс)")
    parser.add_argument("-s", "--speed", type=float, default=MIN_SPEED, help=f"Минимальная скорость (по умолчанию: {MIN_SPEED} Mbps)")
    parser.add_argument("--percent", type=int, default=int(TOP_PERCENT*100), help=f"Процент прокси для теста скорости (по умолчанию: {int(TOP_PERCENT*100)}%%)")
    parser.add_argument("--no-speed", action="store_true", help="Отключить проверку скорости")
    return parser.parse_args()

# Sing-box
SING_VER = "1.11.14"
CORE_NAME = "sing-box.exe" if SYSTEM == "Windows" else "sing-box"

SING_URLS = {
    "Windows": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-windows-amd64.zip",
    "Linux": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-linux-amd64.tar.gz",
    "Darwin": f"https://github.com/SagerNet/sing-box/releases/download/v{SING_VER}/sing-box-{SING_VER}-darwin-amd64.tar.gz"
}

ACTIVE_PROCESSES = []

def cleanup_processes():
    """Очистка процессов при выходе"""
    for p in ACTIVE_PROCESSES:
        try:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=0.5)
        except:
            pass
    if SYSTEM == "Windows":
        try: 
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(["taskkill", "/F", "/IM", CORE_NAME], capture_output=True, startupinfo=si)
            logger.debug("Force cleanup: taskkill completed")
        except Exception as e:
            logger.error(f"Force cleanup failed: {e}")

atexit.register(cleanup_processes)

# ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================

def get_flag_emoji(cc: str) -> str:
    if not cc or len(cc) != 2 or cc == "XX": return "🏳️"
    try: return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397)
    except Exception: return "🏳️"

def robust_base64_decode(s: str) -> str:
    if not s: return ""
    s = s.strip().replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding: s += '=' * (4 - padding)
    try: return base64.b64decode(s, validate=True).decode('utf-8', errors='ignore')
    except: return ""

def find_free_port_block(size: int) -> int:
    """Ищет блок свободных портов (проверяет ВСЕ порты в блоке)"""
    for _ in range(50):
        # Ограничиваем верхнюю границу 49000 для Windows (избегаем excluded ports)
        start = random.randint(20000, 49000)
        # Проверяем все порты в блоке
        if all(is_port_free(start + i) for i in range(size)): 
            return start
    raise RuntimeError("Нет свободных портов")

def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05) # Add timeout to prevent hanging
        return s.connect_ex(('127.0.0.1', port)) != 0

def clean_url(link: str) -> str:
    try: return link.strip().split('#')[0]
    except: return link

def generate_final_link(p: dict, label: str) -> str:
    """Генерация ссылки с новым именем (label)"""
    try:
        link = p['link']
        if link.startswith("vmess://"):
            try:
                b64_str = link[8:]
                j = json.loads(robust_base64_decode(b64_str))
                j['ps'] = label
                new_json = json.dumps(j, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                return f"vmess://{base64.b64encode(new_json).decode('utf-8')}"
            except:
                pass
        return f"{clean_url(link)}#{quote(label)}"
    except:
        return p['link']

def ensure_core():
    # Проверка существования и размера файла
    if os.path.exists(CORE_NAME):
        size = os.path.getsize(CORE_NAME)
        logger.debug(f"Sing-box core found: {CORE_NAME} ({size} bytes)")
        if size > 1024:
            return
        else:
            logger.warning("Core file too small, removing...")
            try: os.remove(CORE_NAME)
            except: pass

    url = SING_URLS.get(SYSTEM)
    if not url: sys.exit(f"OS {SYSTEM} not supported")
    logger.info(f"Downloading Sing-box core from {url}")
    print(f"{Fore.YELLOW}[*] Downloading Sing-box core...{Style.RESET_ALL}")
    
    local_filename = "singbox_pkg"
    try:
        import zipfile, tarfile
        
        # Скачивание с User-Agent
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        )
        with urllib.request.urlopen(req, timeout=30) as response, open(local_filename, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
            
        logger.info(f"Downloaded {len(data)} bytes")
        print(f"{Fore.GREEN}[*] Downloaded: {len(data)} bytes{Style.RESET_ALL}")
        if len(data) < 10000:
            logger.error("Downloaded file too small")
            print(f"{Fore.RED}[!] Download failed (too small). Check VPN/Proxy.{Style.RESET_ALL}")
            sys.exit(1)

        if url.endswith('.zip'):
            with zipfile.ZipFile(local_filename, "r") as z:
                # Ищем исполняемый файл внутри архива
                target_file = None
                for f in z.namelist():
                    if f.endswith("sing-box.exe") or f.endswith("sing-box"):
                        target_file = f
                        break
                
                if target_file:
                    with z.open(target_file) as zf, open(CORE_NAME, "wb") as fo:
                        fo.write(zf.read())
                    logger.info(f"Extracted {target_file}")
                    print(f"{Fore.GREEN}[*] Extracted: {target_file} -> {CORE_NAME}{Style.RESET_ALL}")
                else:
                    logger.error("Binary not found in zip")
                    print(f"{Fore.RED}[!] sing-box binary not found in zip{Style.RESET_ALL}")
                    sys.exit(1)
        else:
            with tarfile.open(local_filename, "r:gz") as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        if f: 
                            with open(CORE_NAME, "wb") as fo: fo.write(f.read())
                        break
        
        if SYSTEM != "Windows": os.chmod(CORE_NAME, 0o755)
        
    except Exception as e: 
        logger.exception("Core installation error")
        print(f"{Fore.RED}Error installing core: {e}{Style.RESET_ALL}")
        # Попытка удалить поврежденный архив
        if os.path.exists(local_filename):
            try: os.remove(local_filename)
            except: pass
        sys.exit(1)
        
    finally:
        if os.path.exists(local_filename): 
            try: os.remove(local_filename)
            except: pass

# ================== УЛУЧШЕННЫЙ ПАРСЕР ==================

def get_first(q: Dict, key: str, default: str = "") -> str:
    val = q.get(key)
    if isinstance(val, list):
        return val[0] if val else default
    return val if val else default

import re

def validate_uuid(u: str) -> bool:
    try:
        uuid.UUID(u)
        return True
    except:
        return False

def validate_ss_method(m: str) -> bool:
    allowed = [
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "chacha20-ietf", "xchacha20-ietf-poly1305"
    ]
    # Строгая проверка: пропускаем только поддерживаемые методы
    if not m or m.lower() not in allowed:
        return False
    return True
    
def parse_proxy(link: str, tag: str) -> Tuple[Optional[Dict], Optional[str], Optional[str], Optional[int]]:
    try:
        link = link.strip()
        if not link: return None, None, None, None
        
        outbound = {}
        proto = "Unknown"
        r_host, r_port = None, None

        # --- VMESS ---
        if link.startswith("vmess://"):
            proto = "VMess"
            b64 = link[8:]
            try: j = json.loads(robust_base64_decode(b64))
            except Exception: return None, None, None, None
            
            r_host = j.get("add") or j.get("host") or j.get("ip")
            try: r_port = int(j.get("port") or 443)
            except Exception: return None, None, None, None

            u_id = j.get("id")
            if not validate_uuid(u_id): return None, None, None, None

            outbound = {
                "type": "vmess", "tag": tag, "server": r_host, "server_port": r_port,
                "uuid": u_id, "security": "auto"
            }
            net = str(j.get("net") or "tcp").lower()
            if net == "ws":
                outbound["transport"] = {"type": "ws", "path": j.get("path", "/"), "headers": {"Host": j.get("host", "")}}
            elif net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": j.get("path", "")}
            
            if str(j.get("tls", "")).lower() in ["tls", "ssl", "1", "true"]:
                outbound["tls"] = {"enabled": True, "server_name": j.get("sni") or j.get("host") or r_host, "insecure": True}

        # --- VLESS / TROJAN ---
        elif link.startswith(("vless://", "trojan://")):
            is_trojan = link.startswith("trojan://")
            proto = "Trojan" if is_trojan else "VLESS"
            try:
                u = urlparse(link)
                q = parse_qs(u.query)
                r_host, r_port = u.hostname, u.port
            except Exception: return None, None, None, None

            outbound = {"type": "trojan" if is_trojan else "vless", "tag": tag, "server": r_host, "server_port": r_port}
            if is_trojan:
                outbound["password"] = unquote(u.username or "")
            else:
                if not validate_uuid(u.username): return None, None, None, None
                outbound["uuid"] = u.username
                outbound["flow"] = get_first(q, "flow")
            
            type_net = get_first(q, "type")
            if type_net == "ws":
                outbound["transport"] = {"type": "ws", "path": get_first(q, "path"), "headers": {"Host": get_first(q, "host")}}
            elif type_net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": get_first(q, "serviceName")}
            
            sec = get_first(q, "security")
            if sec == "tls":
                outbound["tls"] = {"enabled": True, "server_name": get_first(q, "sni", r_host), "insecure": True}
            elif sec == "reality":
                pbk = get_first(q, "pbk")
                if not pbk or len(pbk) < 10: return None, None, None, None # Basic check for public key
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": get_first(q, "sni", r_host),
                    "reality": {"enabled": True, "public_key": pbk, "short_id": get_first(q, "sid")},
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }

        # --- SHADOWSOCKS ---
        elif link.startswith("ss://"):
            proto = "Shadowsocks"
            try:
                raw = link[5:]
                if '@' in raw:
                    userinfo, hostport = raw.rsplit('@', 1)
                else:
                    decoded = robust_base64_decode(raw)
                    userinfo, hostport = decoded.rsplit('@', 1)
                
                if '#' in hostport: hostport = hostport.split('#')[0]
                if '?' in hostport: hostport = hostport.split('?')[0]
                
                r_host, r_port_str = hostport.rsplit(':', 1)
                r_port = int(r_port_str)
                
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    decoded_userinfo = robust_base64_decode(userinfo)
                    if ':' in decoded_userinfo:
                         method, password = decoded_userinfo.split(':', 1)
                    else:
                        return None, None, None, None

                if not validate_ss_method(method): return None, None, None, None

                outbound = {
                    "type": "shadowsocks", "tag": tag, "server": r_host, "server_port": r_port,
                    "method": method, "password": unquote(password)
                }
            except Exception: return None, None, None, None

        # --- HYSTERIA 2 ---
        elif link.startswith("hysteria2://") or link.startswith("hy2://"):
            proto = "Hysteria2"
            try:
                u = urlparse(link)
                q = parse_qs(u.query)
                r_host, r_port = u.hostname, u.port
                outbound = {
                    "type": "hysteria2", "tag": tag, "server": r_host, "server_port": r_port,
                    "password": unquote(u.username or ""),
                    "tls": {"enabled": True, "server_name": get_first(q, "sni", r_host), "insecure": True}
                }
            except Exception: return None, None, None, None

        # Финальная проверка на валидность данных
        if outbound and r_host and r_port:
            if not (1 <= r_port <= 65535): return None, None, None, None # Валидация порта
            if len(str(r_host)) < 3: return None, None, None, None       # Валидация хоста
            return outbound, proto, r_host, r_port
            
        return None, None, None, None
    except Exception as e:
        logger.debug(f"Parsing error for {link[:30]}...: {e}")
        return None, None, None, None

# ================== ЯДРО ПРОВЕРКИ ==================

async def check_proxy_http(session, port, item, my_ip):
    proxy_url = f"http://127.0.0.1:{port}"
    res = {"ok": False, "msg": "Error", "cc": "XX", "ping": 0, "item": item}
    try:
        t0 = time.time()
        # Попытка 1: HTTPS (как раньше)
        target_urls = [PING_URL, "http://cp.cloudflare.com/", "http://www.google.com/generate_204"]
        
        success = False
        for url in target_urls:
            try:
                # Для HTTP используем ssl=False, для HTTPS тоже False (проксируем)
                async with session.get(url, proxy=proxy_url, timeout=TIMEOUT_SEC, ssl=False) as r:
                    if r.status in [200, 204]:
                        ping = int((time.time() - t0) * 1000)
                        res["ping"] = ping
                        success = True
                        break
            except Exception:
                continue
        
        if success:
            try:
                async with session.get(GEO_URL, proxy=proxy_url, timeout=5, ssl=False) as g:
                    d = await g.json()
                    if d.get("query") != my_ip:
                        res["ok"] = True
                        res["cc"] = d.get("countryCode", "XX")
                        res["msg"] = "OK"
            except: 
                res.update({"ok": True, "msg": "No Geo"})

    except Exception as e:
        logger.debug(f"Ping check error for {proxy_url}: {e}")
    return res

async def check_speed_http(session, port, item):
    """Оптимизированный спидтест"""
    proxy_url = f"http://127.0.0.1:{port}"
    downloaded = 0
    t0 = time.time()
    try:
        async with session.get(SPEED_TEST_URL, proxy=proxy_url, timeout=SPEED_TIMEOUT_SEC, ssl=False) as r:
            if r.status == 200:
                async for chunk in r.content.iter_chunked(65536):
                    downloaded += len(chunk)
    except Exception as e:
        logger.debug(f"Speed test error for {proxy_url}: {e}")
        
    duration = time.time() - t0
    # Считаем скорость если скачано хотя бы 100КБ, даже при обрыве
    if duration > 0 and downloaded > 102400:
        speed_mbps = (downloaded * 8 / duration) / 1_000_000
        return round(speed_mbps, 2)
    return 0.0

async def run_singbox_batch(chunk, my_ip, pbar, session, mode="ping"):
    # 1. Поиск свободных портов (Async)
    try: start_port = await asyncio.to_thread(find_free_port_block, len(chunk))
    except Exception as e: 
        logger.error(f"Free port search failed: {e}")
        pbar.update(len(chunk)) 
        return
    
    # 2. Генерация конфига
    logger.debug(f"Generating config for {len(chunk)} proxies at port {start_port}")
    inbounds = [{"type": "mixed", "tag": f"in_{start_port+i}", "listen": "127.0.0.1", "listen_port": start_port+i, "sniff": False} for i in range(len(chunk))]
    
    # Исключаем deprecated типы outbounds (dns, block), если они вдруг есть, и не добавляем dns-out
    outbounds = [item['config'] for item in chunk] + [{"type": "direct", "tag": "direct"}]
    rules = [{"inbound": f"in_{start_port+i}", "outbound": item['tag']} for i, item in enumerate(chunk)]
    
    config = {
        "log": {"disabled": True},
        "dns": {"servers": [{"tag": "google", "address": "8.8.8.8", "detour": "direct"}], "final": "google"},
        "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules, "final": "direct"}
    }
    
    cfg_file = f"temp_{start_port}.json"
    with open(cfg_file, 'w') as f: json.dump(config, f)
    
    proc = None
    stderr_file = None
    try:
        # 3. Запуск Sing-box
        logger.debug(f"Starting sing-box with config {cfg_file}")
        cmd = [f"./{CORE_NAME}", "run", "-c", cfg_file] if SYSTEM != "Windows" else [CORE_NAME, "run", "-c", cfg_file]
        si = subprocess.STARTUPINFO(); si.dwFlags |= subprocess.STARTF_USESHOWWINDOW if SYSTEM == "Windows" else 0
        
        # Настройка окружения для поддержки старого синтаксиса
        env = os.environ.copy()
        env["ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS"] = "true"
        
        # Используем временный файл для stderr, чтобы избежать блокировки буфера
        #stderr_file = open(f"stderr_{start_port}.log", "w+")
        stderr_file = None
        proc = subprocess.Popen(cmd, startupinfo=si if SYSTEM == "Windows" else None, stdout=subprocess.DEVNULL, env=env)
        ACTIVE_PROCESSES.append(proc)
        
        await asyncio.sleep(0.5) # Минимальная пауза перед проверкой порта
        
        # Адаптивное ожидание поднятия порта (макс 6 сек)
        port_up = False
        for _ in range(60):
            if not await asyncio.to_thread(is_port_free, start_port): # Порт занят = sing-box слушает
                port_up = True
                break
            if proc.poll() is not None: # Процесс уже умер
                break
            await asyncio.sleep(0.1)
            
        # 4. Логика проверки
        if proc.poll() is None:
            if not port_up:
                logger.warning(f"Sing-box PID {proc.pid} started but port {start_port} is not listening yet after 6s. Force killing.")
                pbar.update(len(chunk))
                # Принудительно завершаем, чтобы не висел
                proc.terminate()
                return
            else:
                logger.debug(f"Sing-box started successfully (PID: {proc.pid}) and listening on {start_port}")
            # Процесс ЖИВ — проверяем прокси
            if mode == "ping":
                tasks = [check_proxy_http(session, start_port+i, item, my_ip) for i, item in enumerate(chunk)]
                # return_exceptions=True предотвращает падение всего батча из-за одной ошибки
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict):
                        r["item"]["result"] = (r["ok"], f"{r['ping']}ms", r["cc"])
                    pbar.update(1)
            elif mode == "speed":
                # Ограничиваем количество одновременных загрузок ВНУТРИ одного процесса sing-box
                # чтобы не забить канал
                sem_inner = asyncio.Semaphore(5) 
                async def wrapper(p, it):
                    async with sem_inner:
                        it["speed"] = await check_speed_http(session, p, it)
                        pbar.update(1)
                await asyncio.gather(*[wrapper(start_port+i, item) for i, item in enumerate(chunk)], return_exceptions=True)
        else:
            # Процесс УМЕР (падение ядра)
            #stderr_file.seek(0)
            #stderr_out = stderr_file.read()
            logger.error(f"Sing-box died unexpectedly (PID: {proc.pid}).")
            # Если sing-box умер, нужно обновить прогресс-бар, так как мы не проверили эти прокси
            pbar.update(len(chunk))
            
    except Exception as e:
        logger.exception("Batch execution error")
        pbar.update(len(chunk))
    finally:
        # Очистка (усиленная)
        #if stderr_file:
         #   stderr_file.close()
          #  try: os.remove(stderr_file.name)
           # except: pass
            
        if proc: 
            try: 
                proc.terminate()
                if SYSTEM == "Windows":
                     # Принудительное убийство дерева процессов
                     await asyncio.to_thread(subprocess.run, ["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except: pass
            if proc in ACTIVE_PROCESSES: ACTIVE_PROCESSES.remove(proc)
        
        if os.path.exists(cfg_file): 
            try: os.remove(cfg_file)
            except: pass

# ================== MAIN ==================

async def main_async():
    logger.info("Starting Proxy Checker v6.8.3")
    # Парсинг аргументов
    args = parse_args()
    
    # Используем значения из аргументов
    max_ping = args.ping
    min_speed = args.speed
    logger.info(f"Args: ping={max_ping}, speed={min_speed}, percent={args.percent}")
    
    print(f"{Fore.CYAN}{'='*75}\n             > PROXY CHECKER v6.8.4 (Improved) | {SYSTEM}\n{'='*75}{Style.RESET_ALL}")
    print(f"[*] Settings: Max Ping: {Fore.YELLOW}{max_ping}ms{Style.RESET_ALL} | Min Speed: {Fore.YELLOW}{min_speed} Mbps{Style.RESET_ALL} | SpeedTest: {Fore.YELLOW}{args.percent}%{Style.RESET_ALL} лучших")
    
    ensure_core()
    
    my_ip = None
    try:
        async with aiohttp.ClientSession() as s:
            try:
                resp = await s.get("http://ip-api.com/json/", timeout=5)
                my_ip = (await resp.json()).get("query")
            except:
                # Запасной вариант
                resp = await s.get("https://api.ipify.org?format=json", timeout=5)
                my_ip = (await resp.json()).get("ip")
                
        print(f"[*] IP: {Fore.GREEN}{my_ip}{Style.RESET_ALL}")
        logger.info(f"Detected IP: {my_ip}")
    except Exception as e: 
        logger.error(f"IP detection failed: {e}")
        print(f"[*] IP: {Fore.RED}Unknown ({e}){Style.RESET_ALL}")

    os.makedirs(KEYS_DIR, exist_ok=True); os.makedirs(OUT_DIR, exist_ok=True)
    
    # Загрузка ключей
    all_lines = []
    print(f"\n{Fore.BLUE}[*] Loading files:{Style.RESET_ALL}")
    if os.path.exists(KEYS_DIR):
        for fn in os.listdir(KEYS_DIR):
            if fn.endswith(".txt"):
                try:
                    with open(os.path.join(KEYS_DIR, fn), "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        all_lines.extend(lines)
                        print(f"   > {fn}: {len(lines)} lines")
                        logger.info(f"Loaded {len(lines)} lines from {fn}")
                except Exception as e:
                    logger.error(f"Error reading file {fn}: {e}")
    
    total_raw = len(all_lines)
    # Фильтрация коротких строк
    valid_len_keys = [k.strip() for k in all_lines if len(k.strip()) > 10]
    count_short = total_raw - len(valid_len_keys)
    
    # Фильтрация дубликатов (по тексту)
    unique_keys = sorted(list(set(valid_len_keys)))
    count_dupe_raw = len(valid_len_keys) - len(unique_keys)
    
    raw_keys = unique_keys
    
    logger.info(f"Loaded {total_raw} lines. Short: {count_short}. Dupes: {count_dupe_raw}. Unique: {len(raw_keys)}")
    
    print(f"\n{Fore.BLUE}[*] Statistics:{Style.RESET_ALL}")
    print(f"   - Total lines loaded: {total_raw}")
    print(f"   - Short/Empty lines:  {count_short}")
    print(f"   - Duplicates removed: {count_dupe_raw}")
    print(f"   - Ready for parsing:  {len(raw_keys)}")

    # Парсинг
    proxies, fps = [], set()
    count_parse_error = 0
    count_dupe_config = 0
    
    logger.info("Starting parsing...")
    for link in tqdm(raw_keys, desc="Parsing", ncols=70):
        tag = f"p_{uuid.uuid4().hex[:6]}"
        out, proto, _, _ = parse_proxy(link, tag)
        if out:
            # Дедупликация по конфигу
            try:
                fp = hashlib.md5(json.dumps({k:v for k,v in out.items() if k!='tag'}, sort_keys=True).encode()).hexdigest()
                if fp not in fps:
                    fps.add(fp)
                    proxies.append({'link': link, 'tag': tag, 'config': out, 'proto': proto, 'result': None, 'speed': 0.0})
                else:
                    count_dupe_config += 1
            except: 
                count_parse_error += 1
        else:
            count_parse_error += 1

    logger.info(f"Parsing complete. Invalid: {count_parse_error}, DupeConfig: {count_dupe_config}, Valid: {len(proxies)}")
    print(f"{Fore.CYAN}[✓] Parsing Results:{Style.RESET_ALL}")
    print(f"   - Invalid/Unsupported: {count_parse_error}")
    print(f"   - Config Duplicates:   {count_dupe_config}")
    print(f"   - Unique & Valid:      {len(proxies)}")
    if not proxies: 
        logger.warning("No proxies found after parsing")
        return

    # 1. PING TEST
    logger.info("Starting PING test...")
    print(f"\n{Fore.YELLOW}[1/2] Ping Check...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Запуск проверки с параллелизмом: {2}{Style.RESET_ALL}")
    pbar = tqdm(total=len(proxies), desc="Pinging", ncols=75, colour='green')
    chunks = [proxies[i:i+BATCH_SIZE] for i in range(0, len(proxies), BATCH_SIZE)]
    
    # Ограничиваем кол-во одновременных процессов sing-box
    sem = asyncio.Semaphore(2) 
    
    #print(f"{Fore.BLUE}[*] Запуск проверки с параллелизмом: {2}{Style.RESET_ALL}")

    # Создаем одну сессию на весь процесс проверки
    # limit=None: отключаем лимит соединений (мы контролируем их семафором)
    # force_close=True: закрываем сокеты после каждого запроса, чтобы не забивать TIME_WAIT
    connector = aiohttp.TCPConnector(limit=None, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def p_task(c):
            async with sem: 
                # logger.debug(f"Starting batch of {len(c)}")
                await run_singbox_batch(c, my_ip, pbar, session, "ping")
                # logger.debug(f"Finished batch of {len(c)}")
        
        await asyncio.gather(*[p_task(c) for c in chunks], return_exceptions=True)
    pbar.close()

    # FILTER & SORT
    valid = []
    for p in proxies:
        if p.get('result') and isinstance(p['result'], tuple) and len(p['result']) >= 3:
             # p['result'] format: (ok: bool, ping: str, cc: str)
             try:
                 ping_val = int(p['result'][1].replace('ms',''))
                 cc = p['result'][2] # Получаем код страны из результатов
                 
                 # Проверяем, что прокси рабочий, пинг в норме и страна НЕ RU
                 if p['result'][0] and ping_val <= max_ping and cc.upper() != "RU":
                     valid.append(p)
             except: pass
             
    if not valid: 
        logger.warning("No working proxies found after ping test")
        print(f"{Fore.RED}No working proxies found.{Style.RESET_ALL}")
        return

    valid.sort(key=lambda x: int(x['result'][1].replace('ms','')))
    
    # Расчет количества для спидтеста
    count_speedtest = max(1, int(len(valid) * (args.percent / 100.0)))
    top_proxies = valid[:count_speedtest]
    
    logger.info(f"Ping test complete. Alive: {len(valid)}. Selected for SpeedTest: {len(top_proxies)}")
    print(f"{Fore.GREEN}[✓] Alive: {len(valid)} | Top {args.percent}% for SpeedTest: {len(top_proxies)}{Style.RESET_ALL}")

    # 2. SPEED TEST
    if top_proxies and not args.no_speed:
        logger.info("Starting SPEED test...")
        print(f"\n{Fore.MAGENTA}[2/2] Speed Test...{Style.RESET_ALL}")
        pbar_s = tqdm(total=len(top_proxies), desc="SpeedTest", ncols=75, colour='magenta')
        speed_batch = 20
        s_chunks = [top_proxies[i:i+speed_batch] for i in range(0, len(top_proxies), speed_batch)]
        
        # Use semaphore for speed test batches too
        sem_s = asyncio.Semaphore(2)
        
        # Аналогично для спидтеста
        s_connector = aiohttp.TCPConnector(limit=None, force_close=True)
        async with aiohttp.ClientSession(connector=s_connector) as s_session:
            async def s_task(c):
                 async with sem_s: await run_singbox_batch(c, my_ip, pbar_s, s_session, "speed")
            
            await asyncio.gather(*[s_task(c) for c in s_chunks], return_exceptions=True)
        pbar_s.close()

    # ================= SAVE FILES =================

    # FILE 1: ALL LIVE (PING)
    file_all = os.path.join(OUT_DIR, "live_all.txt")
    with open(file_all, "w", encoding="utf-8") as f:
        for p in valid:
            ping, cc = p['result'][1], p['result'][2]
            label = f"{get_flag_emoji(cc)} {cc} | {p['proto']} | ⚡ {ping}"
            f.write(generate_final_link(p, label) + "\n")

    # FILE 2: SPEED ONLY (Sorted by Speed DESC)
    file_speed = os.path.join(OUT_DIR, "live_speed.txt")
    top_proxies.sort(key=lambda x: x.get('speed', 0), reverse=True)
    
    count_speed = 0
    with open(file_speed, "w", encoding="utf-8") as f:
        for p in top_proxies:
            spd = p.get('speed', 0)
            if spd >= min_speed:
                count_speed += 1
                try:
                    ping = p['result'][1]
                    cc = p['result'][2]
                except:
                    ping = "0ms"
                    cc = "XX"

                label = f"{get_flag_emoji(cc)} {cc} | ⚡ {ping} | {p['proto']} |  🚀 {spd} Mbps"
                f.write(generate_final_link(p, label) + "\n")

    logger.info(f"Saved {len(valid)} proxies to {file_all}")
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"📁 1. Все (Ping < {max_ping}ms):      {file_all} ({len(valid)} шт.)")
    print(f"📁 2. Скоростные (>{int(min_speed)}Mbps): {file_speed} ({count_speed} шт.)")
    logger.info(f"Saved {count_speed} speed proxies to {file_speed}")
    logger.info("Finished successfully")
    print(f"{'='*60}{Style.RESET_ALL}")
    
if __name__ == "__main__":
    # if SYSTEM == "Windows": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main_async())
    except KeyboardInterrupt: 
        logger.warning("Interrupted by user")
        print(f"\n{Fore.YELLOW} Прервано пользователем. Очистка...{Style.RESET_ALL}")
        cleanup_processes()
    except Exception as e: 
        logger.exception("Fatal error")
        print(f"\n{Fore.RED} Ошибка: {e}{Style.RESET_ALL}")
        cleanup_processes()
    finally: 
        if sys.stdin.isatty(): input("\nDone. Press Enter...")
