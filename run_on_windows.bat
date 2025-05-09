@echo off
echo [*] WiFi Spammer - только для образовательных целей
echo [*] Установка зависимостей...

pip install -r "%~dp0requirements.txt"
echo [*] Зависимости установлены

echo [*] ВНИМАНИЕ: Для работы программы требуется:
echo [*] 1. Установка Npcap (https://npcap.com/)
echo [*] 2. Запуск от имени администратора
echo [*] 3. Нужно знать имя вашего WiFi адаптера

echo.
echo [*] Доступные сетевые интерфейсы:
netsh wlan show interfaces

echo.
echo [*] Нажмите любую клавишу для продолжения...
pause > nul

set /p interface=Введите имя вашего WiFi интерфейса: 
set /p count=Введите количество фейковых сетей (10-50): 

echo [*] Запуск WiFi спаммера с интерфейсом %interface% и количеством сетей %count%
echo [*] Для остановки нажмите Ctrl+C

python wifi_spammer.py -i "%interface%" -n %count% -d 0.3

pause
