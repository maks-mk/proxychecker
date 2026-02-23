@echo off
chcp 65001 >nul
title Build Proxy Checker v6.5

echo [*] Проверка зависимостей...

:: Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Ошибка: Python не найден в PATH
    echo Установите Python с https://python.org и добавьте в PATH
    pause
    exit /b 1
)

:: Установка PyInstaller если нет
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [*] Установка PyInstaller...
    pip install pyinstaller
)

:: Установка зависимостей проекта
echo [*] Установка requirements...
pip install aiohttp requests tqdm colorama

echo.
echo [*] Очистка старых сборок...
if exist "dist" rd /s /q "dist"
if exist "build" rd /s /q "build"
if exist "*.spec" del /q "*.spec"

echo.
echo [*] Компиляция EXE...
:: Основные параметры:
:: --onefile       = один exe файл
:: --console       = консольное приложение (для CLI)
:: --clean         = очистка кэша
:: --noconfirm     = перезапись без подтверждения
:: --name          = имя выходного файла
:: --add-binary    = включить sing-box.exe (если есть рядом)

python -m PyInstaller ^
    --onefile ^
    --console ^
    --clean ^
    --noconfirm ^
    --name "ProxyChecker_v6.8.4" ^
    --distpath "./dist" ^
    --workpath "./build" ^
    --specpath "./" ^
    --hidden-import aiohttp ^
    --hidden-import aiohttp.web ^
    --hidden-import tqdm ^
    --hidden-import colorama ^
    --hidden-import urllib3 ^
    --collect-all tqdm ^
    --collect-all colorama ^
    "proxy_checker_v6.8.4_speed.py"

if errorlevel 1 (
    echo.
    echo [!] Ошибка сборки!
    pause
    exit /b 1
)

echo.
echo [+] Сборка завершена успешно!
echo Файл: dist\ProxyChecker_v6.8.4.exe
echo.

:: Копирование дополнительных файлов если нужно
if not exist "dist\keys" mkdir "dist\keys"
if not exist "dist\output" mkdir "dist\output"

echo [*] Созданы директории keys\ и output\
echo.
echo [?] Нажмите любую клавишу для выхода...
pause >nul