import logging
import os
import asyncio
import uuid
import urllib3
import statistics
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import FSInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.client.session.aiohttp import AiohttpSession

# Импортируем из engine
from checker_engine import (
    ensure_core, get_my_ip, parse_proxy, 
    check_batch_sync, tcp_precheck_task, 
    GLOBAL_POOL
)

# !!! ВСТАВЬТЕ СЮДА СВОЙ ТОКЕН !!!
TOKEN = "token" 

MAX_FILES_PER_USER = 5
MAX_LINKS_PER_CHECK = 1000
BATCH_SIZE = 8

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

session = AiohttpSession(timeout=120)
bot = Bot(token=TOKEN, session=session)
dp = Dispatcher()

# GLOBAL STATE
USER_BATCHES = {}
USER_FILE_COUNTS = {}
ACTIVE_CHECKS = {}
DATA_LOCK = asyncio.Lock()
TCP_LIMIT = asyncio.Semaphore(200)

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

def get_progress_bar(current, total, length=10):
    if total == 0: return "░" * length
    percent = current / total
    filled = int(length * percent)
    return "█" * filled + "░" * (length - filled)

def get_flag_emoji(cc):
    if not cc or len(cc) != 2 or cc == "XX": return "[XX]"
    return f"[{cc.upper()}]"
    
def get_stop_keyboard():
    builder = InlineKeyboardBuilder()
    builder.button(text="⛔ Остановить проверку", callback_data="stop_process")
    return builder.as_markup()

# === HANDLERS ===

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 <b>Proxy Checker Bot v5.1 (Fixed)</b>\n\n"
        f"⚙️ <b>Лимиты:</b>\n"
        f"• Макс. файлов: <b>{MAX_FILES_PER_USER}</b>\n"
        f"• Макс. ссылок: <b>{MAX_LINKS_PER_CHECK}</b>\n\n"
        "1️⃣ Отправь <b>.txt</b> файлы.\n"
        "2️⃣ Я удалю дубликаты и мусор.\n"
        "3️⃣ Жми <b>/check</b> или кнопку под сообщением.\n"
        "4️⃣ Жми <b>/clear</b> для очистки очереди.",
        parse_mode="HTML"
    )

@dp.message(Command("clear"))
async def cmd_clear(message: types.Message):
    uid = message.from_user.id
    async with DATA_LOCK:
        if uid in USER_BATCHES: del USER_BATCHES[uid]
        if uid in USER_FILE_COUNTS: del USER_FILE_COUNTS[uid]
    await message.answer("🗑 Очередь очищена.")

@dp.message(F.document)
async def handle_document(message: types.Message):
    uid = message.from_user.id
    
    async with DATA_LOCK:
        if uid in ACTIVE_CHECKS: return await message.answer("⚠️ Дождитесь конца текущей проверки!")
        if uid not in USER_BATCHES: USER_BATCHES[uid] = set()
        if uid not in USER_FILE_COUNTS: USER_FILE_COUNTS[uid] = 0
        if USER_FILE_COUNTS[uid] >= MAX_FILES_PER_USER: 
            return await message.answer(f"⛔ Лимит файлов ({MAX_FILES_PER_USER}) превышен.")

    if not message.document.file_name.endswith('.txt'): return await message.answer("❌ Только .txt")
    
    file = await bot.get_file(message.document.file_id)
    tmp = f"temp_{uid}_{uuid.uuid4().hex}.txt"
    
    try: await bot.download_file(file.file_path, tmp, timeout=60)
    except: return await message.answer("❌ Ошибка загрузки.")
    
    added_now = 0
    skipped_limit = 0
    duplicates = 0
    garbage = 0
    total_lines = 0
    
    try:
        with open(tmp, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            total_lines = len(lines)
            
        async with DATA_LOCK:
            curr_len = len(USER_BATCHES[uid])
            for l in lines:
                l = l.strip()
                if len(l) < 10 or l.startswith("#") or "://" not in l: 
                    garbage += 1
                    continue

                # === ЧИСТКА ССЫЛКИ ДЛЯ ПРАВИЛЬНОГО ПОИСКА ДУБЛЕЙ ===
                try:
                    # 1. Отрезаем всё после #
                    clean_url = l.split('#')[0]
                    
                    # 2. Парсим URL для удаления мусорных параметров
                    u = urlparse(clean_url)
                    query = parse_qs(u.query, keep_blank_values=True)
                    
                    # 3. Удаляем параметры, которые портят вид и создают псевдо-дубли
                    changed = False
                    for junk in ['name', 'spider', 'remarks']:
                        if junk in query:
                            del query[junk]
                            changed = True
                    
                    # 4. Собираем чистую ссылку
                    if changed:
                        new_query = urlencode(query, doseq=True)
                        l = urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, ''))
                    else:
                        l = clean_url # Если параметров мусорных нет, просто берем без #
                except:
                    # Если парсинг не удался, пробуем просто отрезать хэш
                    l = l.split('#')[0]
                # =======================================================

                if curr_len + added_now >= MAX_LINKS_PER_CHECK: 
                    skipped_limit += 1
                    continue
                
                # Теперь поиск дублей работает точно
                if l in USER_BATCHES[uid]:
                    duplicates += 1
                    continue
                
                USER_BATCHES[uid].add(l)
                added_now += 1
            USER_FILE_COUNTS[uid] += 1
            total_queue = len(USER_BATCHES[uid])
            
    finally:
        if os.path.exists(tmp): os.remove(tmp)
    
    kb = InlineKeyboardBuilder()
    kb.button(text="🚀 Запустить проверку", callback_data="start_check")
    
    msg = (
        f"📥 <b>Файл принят!</b>\n"
        f"📄 Всего строк: <code>{total_lines}</code>\n"
        f"✅ <b>Добавлено: +{added_now}</b>\n"
        f"🗑 <b>Отсеяно:</b> {duplicates + garbage} (Дубли/Мусор)\n"
        f"📦 <b>Всего в очереди:</b> {total_queue}"
    )
    if skipped_limit > 0: msg += f"\n⚠️ <b>Пропущено:</b> {skipped_limit} (Превышен лимит)"
        
    await message.answer(msg, parse_mode="HTML", reply_markup=kb.as_markup())

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
    async with DATA_LOCK:
        if uid not in USER_BATCHES or not USER_BATCHES[uid]: return await msg.answer("⚠️ Очередь пуста.")
        if uid in ACTIVE_CHECKS: return await msg.answer("⏳ Уже идет.")
        
        # Ссылки здесь уже ЧИСТЫЕ (без name=... и без #...)
        raw_links = list(USER_BATCHES[uid])
        stop_event = asyncio.Event()
        ACTIVE_CHECKS[uid] = stop_event

    st = await msg.answer("⏳ <b>Инициализация...</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
    loop = asyncio.get_running_loop()
    start_t = datetime.now()

    try:
        my_ip = await loop.run_in_executor(None, get_my_ip)
        
        if stop_event.is_set(): raise asyncio.CancelledError
        await st.edit_text(f"⏳ <b>Парсинг {len(raw_links)} ссылок...</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
        
        parsed = []
        for l in raw_links:
            t = f"p_{uuid.uuid4().hex[:8]}"
            out, proto, h, p = parse_proxy(l, t)
            if out: parsed.append({'link': l, 'tag': t, 'config': out, 'proto': proto, 'host': h, 'port': p})
            
        if not parsed: raise ValueError("Нет валидных ссылок")

        # === TCP CHECK ===
        if stop_event.is_set(): raise asyncio.CancelledError
        await st.edit_text(f"📡 <b>TCP Check...</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
        alive = []
        
        async def tcp_guarded(item):
            async with TCP_LIMIT:
                is_ok = await loop.run_in_executor(GLOBAL_POOL, tcp_precheck_task, item['host'], item['port'])
                return item if is_ok else None

        tcp_chunk_size = 200 
        for i in range(0, len(parsed), tcp_chunk_size):
            if stop_event.is_set(): raise asyncio.CancelledError
            chunk = parsed[i:i+tcp_chunk_size]
            tasks = [tcp_guarded(item) for item in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if res and not isinstance(res, Exception): alive.append(res)
            
            try:
                pct = int((i + len(chunk)) / len(parsed) * 100)
                await st.edit_text(f"📡 <b>TCP Check...</b> {pct}%\n✅ Живых IP: <b>{len(alive)}</b>", parse_mode="HTML", reply_markup=get_stop_keyboard())
            except: pass

        if not alive: raise ValueError("Все серверы недоступны (TCP).")

        # === CORE CHECK ===
        chunks = [alive[i:i + BATCH_SIZE] for i in range(0, len(alive), BATCH_SIZE)]
        live_res = []
        processed = 0
        stats_proto = Counter()
        stats_errors = Counter()
        all_pings = []
        
        for i, chunk in enumerate(chunks):
            if stop_event.is_set(): break
            sp = await PORT_MGR.get_port_block(len(chunk))
            
            try:
                pct = int(processed / len(alive) * 100)
                await st.edit_text(
                    f"🚀 <b>Проверка...</b>\n"
                    f"<code>{get_progress_bar(processed, len(alive))}</code> {pct}%\n"
                    f"🔍 <b>Обработано:</b> {processed}/{len(alive)}\n"
                    f"✅ <b>Найдено:</b> {len(live_res)}\n"
                    f"⏱ <b>Время:</b> {(datetime.now() - start_t).seconds} сек",
                    parse_mode="HTML", reply_markup=get_stop_keyboard()
                )
            except: pass
            
            res_batch = await loop.run_in_executor(None, check_batch_sync, chunk, sp, my_ip)
            
            for is_live, ping_val, country_or_err, item in res_batch:
                if is_live:
                    # Ссылка item['link'] уже чистая (спасибо handle_document)
                    # Нам нужно только добавить красивое имя
                    
                    new_name = f"{get_flag_emoji(country_or_err)} | Ping {ping_val}ms | {item['proto']}"
                    
                    # Просто склеиваем чистую ссылку и новое имя
                    live_res.append(f"{item['link']}#{new_name}")
                    
                    stats_proto[item['proto']] += 1
                    all_pings.append(ping_val)
                else:
                    stats_errors[country_or_err] += 1
            processed += len(chunk)

        # === REPORT ===
        is_stopped = stop_event.is_set()
        duration = (datetime.now() - start_t).seconds
        fname = f"live_{datetime.now().strftime('%H-%M')}.txt"
        
        if not live_res:
            if is_stopped:
                await st.edit_text(f"🛑 <b>Проверка остановлена пользователем.</b>\n⏱ Потрачено: {duration} сек \n📊 Проверено: {processed}/{len(parsed)}", parse_mode="HTML")
            else:
                tcp_dead = len(parsed) - len(alive)
                err_list = []
                if tcp_dead > 0: err_list.append(f"🔌 TCP/Port Closed: {tcp_dead}")
                for k, v in stats_errors.most_common(3): err_list.append(f"⚠️ {k}: {v}")
                err_str = "\n".join(err_list) if err_list else "Неизвестная ошибка"
                await st.edit_text(f"😔 <b>Живых серверов не найдено.</b>\n📊 Проверено: {len(parsed)}\n❌ <b>Причины:</b>\n{err_str}", parse_mode="HTML")
        else:
            live_res.sort(key=lambda x: int(x.split('🚀 ')[1].split('ms')[0]) if '🚀' in x else 9999)
            with open(fname, 'w', encoding='utf-8') as f: f.write("\n".join(live_res))
            
            avg = int(statistics.mean(all_pings)) if all_pings else 0
            p_str = "\n".join([f"├ {k}: <b>{v}</b>" for k,v in stats_proto.most_common(3)]) or "└ -"
            e_str = "\n".join([f"├ {k}: {v}" for k,v in stats_errors.most_common(3)]) or "└ -"
            
            head = "🛑 <b>ОСТАНОВЛЕНО</b>" if is_stopped else "✅ <b>ГОТОВО</b>"
            cap = (
                f"{head}\n━━━━━━━━━━━━━━━━━━\n"
                f"🟢 <b>Живых:</b> {len(live_res)}\n"
                f"⏱ <b>Время:</b> {duration} сек\n"
                f"🚀 <b>Ping:</b> {avg}ms\n\n"
                f"📁 <b>Протоколы:</b>\n{p_str}\n\n"
                f"❌ <b>Ошибки:</b>\n{e_str}"
            )
            await st.delete()
            await msg.answer_document(FSInputFile(fname), caption=cap, parse_mode="HTML")
            os.remove(fname)

    except asyncio.CancelledError:
        await st.edit_text("🛑 Отменено.")
    except ValueError as ve:
        await st.edit_text(f"⚠️ {ve}")
    except Exception as e:
        await st.edit_text(f"❌ Ошибка: {e}")
        logging.error(f"Err: {e}", exc_info=True)
    finally:
        async with DATA_LOCK:
            if uid in ACTIVE_CHECKS: del ACTIVE_CHECKS[uid]
            if uid in USER_BATCHES: del USER_BATCHES[uid]
            if uid in USER_FILE_COUNTS: del USER_FILE_COUNTS[uid]

async def main():
    print("⚙️ Проверка компонентов системы...")
    try:
        await asyncio.get_running_loop().run_in_executor(None, ensure_core)
        print("✅ Ядро Sing-box готово.")
    except Exception as e:
        print(f"❌ ФАТАЛЬНАЯ ОШИБКА: Не удалось загрузить ядро.\n{e}")
        return

    await bot.delete_webhook(drop_pending_updates=True)
    print("✅ Bot Started")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass