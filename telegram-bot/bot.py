import logging
import os
import asyncio
import uuid
import urllib3
import statistics
import time
import tempfile
import aiofiles  # Новая зависимость
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import FSInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.exceptions import TelegramRetryAfter, TelegramBadRequest

# Импортируем из engine
from checker_engine import (
    ensure_core, get_my_ip, parse_proxy, 
    check_batch_sync, tcp_precheck_task, 
    clean_url_logic, GLOBAL_POOL
)

# !!! ВСТАВЬТЕ СЮДА СВОЙ ТОКЕН !!!
TOKEN = "token"

# === CONFIG & LIMITS ===
MAX_FILES_PER_USER = 5
MAX_LINKS_PER_CHECK = 1000
BATCH_SIZE = 50 
MAX_FILE_SIZE_MB = 5          # Макс размер файла (защита от DoS)
CHECKS_PER_HOUR = 10          # Лимит проверок в час на юзера
DATA_LIFETIME_HOURS = 2       # Сколько хранить загруженные ссылки в памяти

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

session = AiohttpSession(timeout=120)
bot = Bot(token=TOKEN, session=session)
dp = Dispatcher()

# === GLOBAL STATE ===
USER_LINKS = {} 
USER_FILE_COUNTS = {}
USER_LINKS_TIMESTAMPS = {}    # uid -> timestamp последней активности
USER_RATE_LIMIT = defaultdict(list) # uid -> [timestamps]

ACTIVE_CHECKS = {}
DATA_LOCK = asyncio.Lock()
TCP_LIMIT = asyncio.Semaphore(500)

# === BACKGROUND TASKS ===

async def cleanup_old_data_task():
    """Фоновая задача для очистки памяти от старых данных (Memory Leak Fix)"""
    while True:
        await asyncio.sleep(600)  # Проверяем каждые 10 минут
        try:
            now = datetime.now()
            async with DATA_LOCK:
                expired_users = [
                    uid for uid, ts in USER_LINKS_TIMESTAMPS.items()
                    if now - ts > timedelta(hours=DATA_LIFETIME_HOURS)
                ]
                for uid in expired_users:
                    if uid in USER_LINKS: del USER_LINKS[uid]
                    if uid in USER_FILE_COUNTS: del USER_FILE_COUNTS[uid]
                    if uid in USER_LINKS_TIMESTAMPS: del USER_LINKS_TIMESTAMPS[uid]
                    # Очищаем рейт-лимиты тоже, если юзер давно ушел
                    if uid in USER_RATE_LIMIT: del USER_RATE_LIMIT[uid]
                
                if expired_users:
                    logging.info(f"🧹 GC: Очищены данные {len(expired_users)} неактивных пользователей.")
        except Exception as e:
            logging.error(f"GC Error: {e}")

async def check_rate_limit(uid):
    """Проверка лимита количества запусков (Rate Limit Fix)"""
    now = time.time()
    # Очищаем старые записи (старше 1 часа)
    USER_RATE_LIMIT[uid] = [t for t in USER_RATE_LIMIT[uid] if now - t < 3600]
    
    if len(USER_RATE_LIMIT[uid]) >= CHECKS_PER_HOUR:
        oldest = USER_RATE_LIMIT[uid][0]
        wait_sec = int(3600 - (now - oldest))
        return False, wait_sec
    
    return True, 0

# === PORT MANAGER ===

class PortManager:
    def __init__(self, start=20000, end=55000):
        self.start = start
        self.end = end
        self.current = start
        self.lock = asyncio.Lock()

    async def get_port_block(self, size):
        async with self.lock:
            port = self.current
            self.current += size
            if self.current + size > self.end:
                self.current = self.start
                port = self.start
            return port

PORT_MGR = PortManager()

# === HELPERS ===

def get_time_str(start_ts):
    seconds = int(time.time() - start_ts)
    m, s = divmod(seconds, 60)
    return f"{m:02d}:{s:02d}"

def get_progress_bar(current, total, length=12):
    if total == 0: return "░" * length
    percent = current / total
    filled = int(length * percent)
    return "█" * filled + "░" * (length - filled)

def get_flag_emoji(cc):
    if not cc or len(cc) != 2 or cc == "XX": return "🏳️"
    try: return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except: return "🏳️"
    
def get_stop_keyboard():
    builder = InlineKeyboardBuilder()
    builder.button(text="⛔ Стоп", callback_data="stop_process")
    return builder.as_markup()

async def safe_edit_text(msg: types.Message, text, reply_markup=None):
    """Безопасное редактирование с защитой от FloodWait и BadRequest"""
    try:
        await msg.edit_text(text, parse_mode="HTML", reply_markup=reply_markup)
    except TelegramRetryAfter as e:
        await asyncio.sleep(e.retry_after)
        try:
            await msg.edit_text(text, parse_mode="HTML", reply_markup=reply_markup)
        except: pass
    except TelegramBadRequest:
        pass # Сообщение не изменилось или удалено
    except Exception:
        pass

# === HANDLERS ===

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 <b>Proxy Checker Bot v6.0 (Secure)</b>\n"
        "Защищенная и оптимизированная версия.\n\n"
        f"⚙️ <b>Лимиты:</b>\n"
        f"• Файл: до <b>{MAX_FILE_SIZE_MB} МБ</b>\n"
        f"• Проверок: <b>{CHECKS_PER_HOUR}</b> в час\n"
        f"• Хранение данных: <b>{DATA_LIFETIME_HOURS}</b> часа\n\n"
        "1️⃣ Отправь <b>.txt</b> файлы.\n"
        "2️⃣ Жми <b>/check</b>.\n"
        "3️⃣ Жми <b>/clear</b>.",
        parse_mode="HTML"
    )

@dp.message(Command("clear"))
async def cmd_clear(message: types.Message):
    uid = message.from_user.id
    async with DATA_LOCK:
        if uid in USER_LINKS: del USER_LINKS[uid]
        if uid in USER_FILE_COUNTS: del USER_FILE_COUNTS[uid]
        if uid in USER_LINKS_TIMESTAMPS: del USER_LINKS_TIMESTAMPS[uid]
    await message.answer("🗑 Очередь очищена.")

@dp.message(F.document)
async def handle_document(message: types.Message):
    uid = message.from_user.id
    
    # 1. Проверка размера файла (Large File Blocking Fix)
    if message.document.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return await message.answer(f"❌ Файл слишком большой! Максимум {MAX_FILE_SIZE_MB} МБ.")

    async with DATA_LOCK:
        if uid in ACTIVE_CHECKS: return await message.answer("⚠️ Дождитесь конца проверки!")
        if uid not in USER_LINKS: USER_LINKS[uid] = []
        if uid not in USER_FILE_COUNTS: USER_FILE_COUNTS[uid] = 0
        
        # Обновляем timestamp активности (для GC)
        USER_LINKS_TIMESTAMPS[uid] = datetime.now()

        if USER_FILE_COUNTS[uid] >= MAX_FILES_PER_USER: 
            return await message.answer("⛔ Лимит количества файлов.")

    if not message.document.file_name.endswith('.txt'): 
        return await message.answer("❌ Только .txt")
    
    file = await bot.get_file(message.document.file_id)
    
    # 2. Безопасная работа с временными файлами (Temp File Fix)
    # Используем системную temp директорию
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp_file:
        tmp_path = tmp_file.name

    try:
        await bot.download_file(file.file_path, tmp_path, timeout=60)
        
        lines_added = 0
        # 3. Асинхронное чтение файла (Non-blocking I/O)
        async with aiofiles.open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
            async for line in f:
                l = line.strip()
                if len(l) > 10 and not l.startswith("#"):
                    USER_LINKS[uid].append(l)
                    lines_added += 1
                    # Защита от слишком больших списков внутри файла
                    if len(USER_LINKS[uid]) > MAX_LINKS_PER_CHECK * 2:
                        break
        
        USER_FILE_COUNTS[uid] += 1
        
        kb = InlineKeyboardBuilder()
        kb.button(text="🚀 Запустить проверку", callback_data="start_check")
        
        warn = ""
        if len(USER_LINKS[uid]) >= MAX_LINKS_PER_CHECK:
            warn = f"\n⚠️ Лимит ссылок! Будут проверены первые {MAX_LINKS_PER_CHECK}."

        await message.answer(
            f"📥 Принято: {lines_added} строк.\n"
            f"Всего в очереди: {len(USER_LINKS[uid])}{warn}", 
            reply_markup=kb.as_markup()
        )

    except Exception as e:
        await message.answer(f"❌ Ошибка обработки: {e}")
    finally:
        # Гарантированное удаление
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except: pass

@dp.callback_query(F.data == "start_check")
async def cb_start(cb: types.CallbackQuery):
    await cb.answer()
    await cmd_check(cb.message, cb.from_user.id)

@dp.callback_query(F.data == "stop_process")
async def cb_stop(cb: types.CallbackQuery):
    uid = cb.from_user.id
    async with DATA_LOCK:
        if uid in ACTIVE_CHECKS:
            ACTIVE_CHECKS[uid].set()
            await cb.answer("🛑 Останавливаю...", show_alert=True)
        else:
            await cb.answer("Нечего останавливать.")

@dp.message(Command("check"))
async def cmd_check_cmd(msg: types.Message):
    await cmd_check(msg, msg.from_user.id)

async def cmd_check(msg: types.Message, uid: int):
    # 4. Проверка Rate Limit
    can_check, wait_time = await check_rate_limit(uid)
    if not can_check:
        return await msg.answer(f"⏳ <b>Лимит превышен!</b>\nПодождите {wait_time // 60} мин. {wait_time % 60} сек.", parse_mode="HTML")

    async with DATA_LOCK:
        if uid not in USER_LINKS or not USER_LINKS[uid]: return await msg.answer("⚠️ Очередь пуста.")
        if uid in ACTIVE_CHECKS: return await msg.answer("⏳ Уже идет.")
        
        # Обновляем активность
        USER_LINKS_TIMESTAMPS[uid] = datetime.now()
        # Фиксируем запуск в рейт-лимите
        USER_RATE_LIMIT[uid].append(time.time())

        raw_links = USER_LINKS[uid][:MAX_LINKS_PER_CHECK] # Hard limit
        stop_event = asyncio.Event()
        ACTIVE_CHECKS[uid] = stop_event

    st = await msg.answer("⏳ <b>Инициализация...</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
    loop = asyncio.get_running_loop()
    start_ts = time.time()

    try:
        my_ip = await loop.run_in_executor(None, get_my_ip)
        
        # === 1. PARSING ===
        await safe_edit_text(st, f"🧹 <b>Чистка и дедупликация...</b>", get_stop_keyboard())
        
        parsed = []
        unique_fp = set()
        
        for l in raw_links:
            if stop_event.is_set(): raise asyncio.CancelledError
            
            cl = clean_url_logic(l)
            t = f"p_{uuid.uuid4().hex[:8]}"
            out, proto, h, p = parse_proxy(cl, t)
            
            if out and h and p:
                auth = str(out.get("uuid", out.get("password", "")))
                key = f"{h}:{p}:{proto}:{auth}"
                
                if key not in unique_fp:
                    unique_fp.add(key)
                    parsed.append({'link': cl, 'tag': t, 'config': out, 'proto': proto, 'host': h, 'port': p})
            
            if len(parsed) >= MAX_LINKS_PER_CHECK: break

        if not parsed: raise ValueError("Нет валидных ссылок")

        # === 2. TCP CHECK ===
        alive = []
        last_update = 0
        
        async def tcp_guarded(item):
            async with TCP_LIMIT:
                is_ok = await loop.run_in_executor(GLOBAL_POOL, tcp_precheck_task, item['host'], item['port'])
                return item if is_ok else None

        for i in range(0, len(parsed), 200):
            if stop_event.is_set(): raise asyncio.CancelledError
            chunk = parsed[i:i+200]
            tasks = [tcp_guarded(item) for item in chunk]
            results = await asyncio.gather(*tasks)
            alive.extend([r for r in results if r])
            
            if time.time() - last_update > 2.0:
                pct = int((i + len(chunk)) / len(parsed) * 100)
                await safe_edit_text(st,
                    f"📡 <b>TCP Scanning...</b> {pct}%\n"
                    f"<code>{get_progress_bar(i + len(chunk), len(parsed))}</code>\n\n"
                    f"🔎 Проверено: <b>{i + len(chunk)}</b>\n"
                    f"🟢 Доступно: <b>{len(alive)}</b>", 
                    get_stop_keyboard()
                )
                last_update = time.time()

        if not alive: raise ValueError("Все серверы недоступны (TCP).")

        # === 3. HTTP CHECK ===
        chunks = [alive[i:i + BATCH_SIZE] for i in range(0, len(alive), BATCH_SIZE)]
        live_res = []
        processed = 0
        stats_proto = Counter()
        all_pings = []
        last_update = 0
        
        for i, chunk in enumerate(chunks):
            if stop_event.is_set(): break
            
            if time.time() - last_update > 2.5 or i == 0:
                elapsed = time.time() - start_ts
                speed = processed / elapsed if elapsed > 0 else 0
                pct = int(processed / len(alive) * 100)
                
                await safe_edit_text(st,
                    f"🚀 <b>Full Checking...</b> {pct}%\n"
                    f"<code>{get_progress_bar(processed, len(alive))}</code>\n\n"
                    f"📊 Прогресс: <b>{processed} / {len(alive)}</b>\n"
                    f"✅ Найдено: <b>{len(live_res)}</b>\n"
                    f"⚡ Скорость: <b>{speed:.1f} prx/s</b>\n"
                    f"⏱ Время: <b>{get_time_str(start_ts)}</b>",
                    get_stop_keyboard()
                )
                last_update = time.time()

            sp = await PORT_MGR.get_port_block(len(chunk))
            
            try:
                res_batch = await loop.run_in_executor(None, check_batch_sync, chunk, sp, my_ip)
                for is_live, ping_val, cc, item in res_batch:
                    if is_live:
                        new_name = f"{get_flag_emoji(cc)} | Ping {ping_val}ms | {item['proto']}"
                        live_res.append(f"{item['link']}#{new_name}")
                        stats_proto[item['proto']] += 1
                        all_pings.append(ping_val)
                processed += len(chunk)
            except Exception:
                processed += len(chunk)

        # === REPORT ===
        is_stopped = stop_event.is_set()
        duration_sec = time.time() - start_ts
        fname = f"live_{datetime.now().strftime('%H-%M')}.txt"
        
        if not live_res:
             await safe_edit_text(st, f"😔 <b>Живых серверов не найдено.</b>\nПопробуйте другие прокси.")
        else:
            live_res.sort(key=lambda x: int(x.split('🚀 ')[1].split('ms')[0]) if '🚀' in x else 9999)
            with open(fname, 'w', encoding='utf-8') as f: f.write("\n".join(live_res))
            
            avg = int(statistics.mean(all_pings)) if all_pings else 0
            best = min(all_pings) if all_pings else 0
            
            countries = Counter([x.split(maxsplit=1)[0] for x in [l.split('#')[-1] for l in live_res]])
            c_str = ", ".join([f"{k} {v}" for k,v in countries.most_common(5)])
            p_str = "\n".join([f"├ {k}: <b>{v}</b>" for k,v in stats_proto.most_common(3)]) or "└ -"
            
            head = "🛑 <b>СТОП</b>" if is_stopped else "✅ <b>ГОТОВО</b>"
            cap = (
                f"{head}\n━━━━━━━━━━━━━━━━━━\n"
                f"📊 <b>Результат:</b> {len(live_res)} / {len(parsed)}\n"
                f"🌍 <b>Страны:</b> {c_str}\n"
                f"⏱ <b>Время:</b> {get_time_str(start_ts)}\n"
                f"🚀 <b>Ping:</b> Avg {avg}ms | Best {best}ms\n\n"
                f"📁 <b>Протоколы:</b>\n{p_str}"
            )
            await st.delete()
            await msg.answer_document(FSInputFile(fname), caption=cap, parse_mode="HTML")
            os.remove(fname)

    except asyncio.CancelledError:
        await safe_edit_text(st, "🛑 Отменено пользователем.")
    except ValueError as ve:
        await safe_edit_text(st, f"⚠️ {ve}")
    except Exception as e:
        await safe_edit_text(st, f"❌ Ошибка: {e}")
        logging.error(f"Err: {e}", exc_info=True)
    finally:
        async with DATA_LOCK:
            if uid in ACTIVE_CHECKS: del ACTIVE_CHECKS[uid]
            # Данные не удаляем, они удалятся GC через 2 часа

async def main():
    print("⚙️ Проверка Sing-box...")
    try:
        await asyncio.get_running_loop().run_in_executor(None, ensure_core)
        print("✅ Ядро готово.")
    except Exception as e:
        print(f"❌ Ошибка ядра: {e}")
        return

    # Запуск фонового сборщика мусора
    asyncio.create_task(cleanup_old_data_task())

    await bot.delete_webhook(drop_pending_updates=True)
    print("✅ Bot Started (v6.0 Secure)")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass