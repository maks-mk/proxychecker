import logging
import os
import asyncio
import uuid
import urllib3
import statistics
import time
import tempfile
import aiofiles
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import FSInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.exceptions import TelegramRetryAfter, TelegramBadRequest

# Импортируем движок
from checker_engine import (
    ensure_core, get_my_ip, parse_proxy, 
    check_batch_sync, tcp_precheck_task, 
    clean_url_logic, GLOBAL_POOL
)

# !!! ВСТАВЬТЕ СЮДА СВОЙ ТОКЕН !!!
TOKEN = "7829664819:AAG6gFAWg0m1B2fBFwhXzyzxK3BTGj5feMY"

# === ADMIN CONFIG ===
ADMIN_IDS = [
    1219886637
]

# === CONFIG & LIMITS ===
MAX_FILES_PER_USER = 5
MAX_LINKS_PER_CHECK = 1000
BATCH_SIZE = 50 
MAX_FILE_SIZE_MB = 5          
CHECKS_PER_HOUR = 10          
DATA_LIFETIME_HOURS = 2       

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

session = AiohttpSession(timeout=120)
bot = Bot(token=TOKEN, session=session)
dp = Dispatcher()

# === GLOBAL STATE ===
USER_LINKS = {} 
USER_FILE_COUNTS = {}
USER_LINKS_TIMESTAMPS = {}    
USER_RATE_LIMIT = defaultdict(list) 

ACTIVE_CHECKS = {}
DATA_LOCK = asyncio.Lock()
TCP_LIMIT = asyncio.Semaphore(500)

# === BACKGROUND TASKS ===

async def cleanup_old_data_task():
    """Очистка памяти от старых данных"""
    while True:
        await asyncio.sleep(600)
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
                    if uid in USER_RATE_LIMIT: del USER_RATE_LIMIT[uid]
                
                if expired_users:
                    logging.info(f"🧹 GC: Очищены данные {len(expired_users)} пользователей.")
        except Exception as e:
            logging.error(f"GC Error: {e}")

async def check_rate_limit(uid):
    """Лимит запусков в час"""
    now = time.time()
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

def get_progress_bar(current, total, length=10):
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
    try:
        await msg.edit_text(text, parse_mode="HTML", reply_markup=reply_markup)
    except TelegramRetryAfter as e:
        await asyncio.sleep(e.retry_after)
        try: await msg.edit_text(text, parse_mode="HTML", reply_markup=reply_markup)
        except: pass
    except TelegramBadRequest: pass
    except Exception: pass

# === USER HANDLERS ===

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 <b>Proxy Checker Bot</b>\n"
        f"⚙️ <b>Лимиты:</b>\n"
        f"• Файл: до <b>{MAX_FILE_SIZE_MB} МБ</b>\n"
        f"• Проверок: <b>{CHECKS_PER_HOUR}</b> в час\n\n"
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
    
    if message.document.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return await message.answer(f"❌ Файл слишком большой! Максимум {MAX_FILE_SIZE_MB} МБ.")

    async with DATA_LOCK:
        if uid in ACTIVE_CHECKS: return await message.answer("⚠️ Дождитесь конца проверки!")
        if uid not in USER_LINKS: USER_LINKS[uid] = []
        if uid not in USER_FILE_COUNTS: USER_FILE_COUNTS[uid] = 0
        USER_LINKS_TIMESTAMPS[uid] = datetime.now()

        if USER_FILE_COUNTS[uid] >= MAX_FILES_PER_USER: 
            return await message.answer("⛔ Лимит количества файлов.")

    if not message.document.file_name.endswith('.txt'): 
        return await message.answer("❌ Только .txt")
    
    file = await bot.get_file(message.document.file_id)
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp_file:
        tmp_path = tmp_file.name

    try:
        await bot.download_file(file.file_path, tmp_path, timeout=60)
        lines_added = 0
        async with aiofiles.open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
            async for line in f:
                l = line.strip()
                if len(l) > 10 and not l.startswith("#"):
                    USER_LINKS[uid].append(l)
                    lines_added += 1
                    if len(USER_LINKS[uid]) > MAX_LINKS_PER_CHECK * 2: break
        
        USER_FILE_COUNTS[uid] += 1
        kb = InlineKeyboardBuilder()
        kb.button(text="🚀 Запустить проверку", callback_data="start_check")
        warn = ""
        if len(USER_LINKS[uid]) >= MAX_LINKS_PER_CHECK:
            warn = f"\n⚠️ Лимит ссылок! Будут проверены первые {MAX_LINKS_PER_CHECK}."

        await message.answer(f"📥 Принято: {lines_added} строк.\nВсего: {len(USER_LINKS[uid])}{warn}", reply_markup=kb.as_markup())
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")
    finally:
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
    can_check, wait_time = await check_rate_limit(uid)
    if not can_check:
        return await msg.answer(f"⏳ <b>Лимит превышен!</b>\nЖдать {wait_time // 60} мин.", parse_mode="HTML")

    async with DATA_LOCK:
        if uid not in USER_LINKS or not USER_LINKS[uid]: return await msg.answer("⚠️ Очередь пуста.")
        if uid in ACTIVE_CHECKS: return await msg.answer("⏳ Уже идет.")
        USER_LINKS_TIMESTAMPS[uid] = datetime.now()
        USER_RATE_LIMIT[uid].append(time.time())

        raw_links = USER_LINKS[uid][:MAX_LINKS_PER_CHECK]
        stop_event = asyncio.Event()
        ACTIVE_CHECKS[uid] = stop_event

    st = await msg.answer("⏳ <b>Инициализация...</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
    loop = asyncio.get_running_loop()
    start_ts = time.time()

    try:
        my_ip = await loop.run_in_executor(None, get_my_ip)
        await safe_edit_text(st, f"🧹 <b>Чистка и дедупликация...</b>", get_stop_keyboard())
        
        # === PARSING ===
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

        # === TCP SCAN ===
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

        # === HTTP CHECK ===
        chunks = [alive[i:i + BATCH_SIZE] for i in range(0, len(alive), BATCH_SIZE)]
        def extract_ping(entry: str) -> int:
            try:
                name = entry.split('#', 1)[1]
                idx = name.find('Ping ')
                if idx == -1: return 9999
                return int(name[idx + len('Ping '):].split('ms')[0])
            except: return 9999

        live_res = []
        processed = 0
        stats_proto = Counter()
        all_pings = []
        last_update = 0
        
        for i, chunk in enumerate(chunks):
            if stop_event.is_set(): break
            
            # --- ВОТ ЗДЕСЬ ВОЗВРАЩЕН ДЕТАЛЬНЫЙ ВЫВОД ---
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
            # ---------------------------------------------

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
            except: processed += len(chunk)

        # === REPORT ===
        is_stopped = stop_event.is_set()
        fname = f"live_{datetime.now().strftime('%H-%M')}.txt"
        
        if not live_res:
             await safe_edit_text(st, f"😔 <b>Ничего не найдено.</b>")
        else:
            live_res.sort(key=extract_ping)
            with open(fname, 'w', encoding='utf-8') as f:
                f.write("\n".join(live_res))
            
            avg = int(statistics.mean(all_pings)) if all_pings else 0
            best = min(all_pings) if all_pings else 0
            countries = Counter([x.split(maxsplit=1)[0] for x in [l.split('#')[-1] for l in live_res]])
            c_str = ", ".join([f"{k} {v}" for k,v in countries.most_common(5)])
            p_str = "\n".join([f"├ {k}: <b>{v}</b>" for k,v in stats_proto.most_common(3)]) or "└ -"
            
            head = "🛑 <b>СТОП</b>" if is_stopped else "✅ <b>ГОТОВО</b>"
            # --- ДЕТАЛЬНЫЙ КАПШН ИТОГА ---
            cap = (
                f"{head}\n━━━━━━━━━━━━━━━━━━\n"
                f"📊 <b>Результат:</b> {len(live_res)} / {len(parsed)}\n"
                f"🌍 <b>Страны:</b> {c_str}\n"
                f"⏱ <b>Время:</b> {get_time_str(start_ts)}\n"
                f"🚀 <b>Ping:</b> Avg {avg}ms | Best {best}ms\n\n"
                f"📁 <b>Протоколы:</b>\n{p_str}"
            )
            # -----------------------------
            await st.delete()
            await msg.answer_document(FSInputFile(fname), caption=cap, parse_mode="HTML")
            os.remove(fname)

    except asyncio.CancelledError: await safe_edit_text(st, "🛑 Отмена.")
    except ValueError as ve: await safe_edit_text(st, f"⚠️ {ve}")
    except Exception as e:
        await safe_edit_text(st, f"❌ Err: {e}")
        logging.error(f"E: {e}", exc_info=True)
    finally:
        async with DATA_LOCK:
            if uid in ACTIVE_CHECKS: del ACTIVE_CHECKS[uid]

# ==========================================
#              ADMIN PANEL
# ==========================================

def get_admin_keyboard():
    kb = InlineKeyboardBuilder()
    kb.button(text="📊 Статистика", callback_data="adm_stats")
    kb.button(text="🚀 Активные процессы", callback_data="adm_active")
    kb.button(text="📋 Список очередей", callback_data="adm_users")
    kb.button(text="🗑 Очистить ВСЁ", callback_data="adm_flush_ask")
    kb.button(text="❌ Закрыть", callback_data="adm_close")
    kb.adjust(1)
    return kb.as_markup()

@dp.message(Command("admin"))
async def cmd_admin_menu(message: types.Message):
    if message.from_user.id not in ADMIN_IDS: return
    await message.answer("🔒 <b>Админка</b>", reply_markup=get_admin_keyboard(), parse_mode="HTML")

@dp.callback_query(F.data == "adm_main")
async def cb_admin_main(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    await safe_edit_text(cb.message, "🔒 <b>Админка</b>", get_admin_keyboard())
    await cb.answer()

@dp.callback_query(F.data == "adm_stats")
async def cb_admin_stats(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    async with DATA_LOCK:
        u_cnt = len(USER_LINKS)
        l_cnt = sum(len(v) for v in USER_LINKS.values())
        f_cnt = sum(USER_FILE_COUNTS.values())
        al_cnt = len([u for u, t in USER_RATE_LIMIT.items() if t])
    
    mem = "N/A"
    try:
        import psutil
        mem = f"{psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024:.1f} MB"
    except: pass

    text = (f"📊 <b>Статистика</b>\nUsers: <b>{u_cnt}</b>\nLinks: <b>{l_cnt}</b>\nFiles: <b>{f_cnt}</b>\nLimits: <b>{al_cnt}</b>\nRAM: <b>{mem}</b>")
    kb = InlineKeyboardBuilder()
    kb.button(text="🔄 Обновить", callback_data="adm_stats")
    kb.button(text="⬅️ Назад", callback_data="adm_main")
    await safe_edit_text(cb.message, text, kb.as_markup())
    await cb.answer()

@dp.callback_query(F.data == "adm_active")
async def cb_admin_active(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    async with DATA_LOCK:
        active = list(ACTIVE_CHECKS.keys())
    text = "🚀 <b>Активные:</b>\n" + (f"\n".join([f"<code>{u}</code>" for u in active]) if active else "Нет")
    kb = InlineKeyboardBuilder()
    if active: kb.button(text="⛔ STOP ALL", callback_data="adm_stop_all")
    kb.button(text="⬅️ Назад", callback_data="adm_main")
    await safe_edit_text(cb.message, text, kb.as_markup())
    await cb.answer()

@dp.callback_query(F.data == "adm_users")
async def cb_admin_users(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    async with DATA_LOCK:
        text = "📂 <b>Юзеры:</b>\n"
        for u, l in USER_LINKS.items(): text += f"<code>{u}</code>: {len(l)} links\n"
        if not USER_LINKS: text += "Пусто"
        text += "\nClean: /clear_id ID"
    kb = InlineKeyboardBuilder()
    kb.button(text="🔄 Обновить", callback_data="adm_users")
    kb.button(text="⬅️ Назад", callback_data="adm_main")
    await safe_edit_text(cb.message, text, kb.as_markup())
    await cb.answer()

@dp.callback_query(F.data == "adm_stop_all")
async def cb_admin_stop_all(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    async with DATA_LOCK:
        for u, ev in ACTIVE_CHECKS.items(): ev.set()
    await cb.answer("🛑 Signal Sent", show_alert=True)
    await cb_admin_active(cb)

@dp.callback_query(F.data == "adm_flush_ask")
async def cb_admin_flush_ask(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    kb = InlineKeyboardBuilder()
    kb.button(text="✅ ДА, УДАЛИТЬ", callback_data="adm_flush_confirm")
    kb.button(text="❌ ОТМЕНА", callback_data="adm_main")
    await safe_edit_text(cb.message, "⚠️ <b>Удалить ВСЕ данные пользователей?</b>", kb.as_markup())
    await cb.answer()

@dp.callback_query(F.data == "adm_flush_confirm")
async def cb_admin_flush_confirm(cb: types.CallbackQuery):
    if cb.from_user.id not in ADMIN_IDS: return
    async with DATA_LOCK:
        USER_LINKS.clear(); USER_FILE_COUNTS.clear(); USER_LINKS_TIMESTAMPS.clear(); USER_RATE_LIMIT.clear()
    await cb.answer("✅ Очищено!", show_alert=True)
    await cb_admin_main(cb)

@dp.callback_query(F.data == "adm_close")
async def cb_admin_close(cb: types.CallbackQuery):
    await cb.message.delete()

@dp.message(Command("clear_id"))
async def cmd_admin_clear_id(message: types.Message):
    if message.from_user.id not in ADMIN_IDS: return
    try:
        tid = int(message.text.split()[1])
        async with DATA_LOCK:
            if tid in USER_LINKS: del USER_LINKS[tid]
            if tid in USER_FILE_COUNTS: del USER_FILE_COUNTS[tid]
            if tid in USER_LINKS_TIMESTAMPS: del USER_LINKS_TIMESTAMPS[tid]
            if tid in USER_RATE_LIMIT: del USER_RATE_LIMIT[tid]
            if tid in ACTIVE_CHECKS: ACTIVE_CHECKS[tid].set(); del ACTIVE_CHECKS[tid]
        await message.answer(f"✅ User {tid} cleared.")
    except: await message.answer("Format: /clear_id 12345")

# === MAIN ===

async def main():
    print("⚙️ Checking Core...")
    try:
        await asyncio.get_running_loop().run_in_executor(None, ensure_core)
        print("✅ Core Ready.")
    except Exception as e:
        print(f"❌ Core Error: {e}")
        return

    asyncio.create_task(cleanup_old_data_task())
    await bot.delete_webhook(drop_pending_updates=True)
    print("✅ Bot Started with Admin Panel & Detailed Stats")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass