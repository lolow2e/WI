#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WiFi Scanner - Инструмент для сканирования и отображения доступных WiFi сетей
ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ
"""

from scapy.all import *
import os
import time
import argparse
from collections import defaultdict

# Словарь для хранения обнаруженных сетей
networks = defaultdict(lambda: {"beacons": 0, "channel": None, "encryption": set(), "clients": set()})

def handle_packet(packet):
    """Обработка пакета Beacon"""
    if packet.haslayer(Dot11Beacon):
        # Извлечение BSSID
        bssid = packet[Dot11].addr2
        
        # Извлечение SSID
        try:
            ssid = packet[Dot11Elt].info.decode('utf-8')
        except:
            ssid = f"Скрытая сеть ({bssid})"
            
        # Увеличиваем счетчик beacon'ов для этой сети
        networks[bssid]["beacons"] += 1
        networks[bssid]["ssid"] = ssid
        
        # Обновляем силу сигнала
        try:
            signal_strength = -(256-ord(packet.notdecoded[-4:-3]))
        except:
            signal_strength = -100
        networks[bssid]["signal"] = signal_strength
        
        # Получаем канал
        try:
            for channel_item in packet[Dot11Elt]:
                if channel_item.ID == 3:  # Элемент с ID 3 содержит информацию о канале
                    networks[bssid]["channel"] = ord(channel_item.info)
        except:
            networks[bssid]["channel"] = "Неизв."
        
        # Проверяем шифрование
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        if "privacy" in cap:
            networks[bssid]["encryption"].add("WEP/WPA/WPA2")
        else:
            networks[bssid]["encryption"].add("Открытая")

def print_networks():
    """Вывод информации о найденных сетях"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n{:<4} {:<18} {:<25} {:<8} {:<12} {:<15}".format(
        "№", "BSSID", "SSID", "Канал", "Сигнал (dBm)", "Шифрование"))
    print("-" * 85)
    
    for i, (bssid, data) in enumerate(sorted(networks.items(), 
                                          key=lambda x: x[1]["signal"] if x[1]["signal"] else -100, 
                                          reverse=True), 1):
        print("{:<4} {:<18} {:<25} {:<8} {:<12} {:<15}".format(
            i, 
            bssid, 
            data["ssid"][:23] + ".." if len(data["ssid"]) > 25 else data["ssid"], 
            data["channel"] if data["channel"] else "?",
            data["signal"] if "signal" in data else "?",
            ", ".join(data["encryption"])
        ))
    
    print("\n[*] Всего найдено сетей: {}".format(len(networks)))
    print("[*] Нажмите Ctrl+C для остановки сканирования\n")

def channel_hopper(interface):
    """Переключение каналов WiFi"""
    while True:
        try:
            for channel in range(1, 14):  # Каналы WiFi 1-13
                # В Linux
                if os.name != 'nt':
                    os.system(f"iw dev {interface} set channel {channel}")
                # В Windows просто ждем, переключение каналов сложнее и зависит от драйверов
                time.sleep(0.5)
        except KeyboardInterrupt:
            break

def main():
    parser = argparse.ArgumentParser(description='WiFi Scanner - Сканер WiFi сетей')
    parser.add_argument('-i', '--interface', default="wlan0", help='Сетевой интерфейс')
    parser.add_argument('-t', '--time', type=int, default=30, help='Время сканирования в секундах')
    args = parser.parse_args()
    
    # Проверяем права администратора
    if os.name != 'nt':  # Не в Windows
        if os.geteuid() != 0:
            print("Этот скрипт требует привилегий администратора. Запустите с sudo.")
            return
    
    print(f"[*] Начинаем сканирование WiFi сетей на интерфейсе {args.interface}")
    print("[*] Сканирование займет примерно {0} секунд...".format(args.time))
    
    # Запускаем переключение каналов в отдельном потоке
    import threading
    channel_hopper_thread = threading.Thread(target=channel_hopper, args=(args.interface,))
    channel_hopper_thread.daemon = True
    channel_hopper_thread.start()
    
    # Запускаем сниффер
    start_time = time.time()
    
    try:
        # Обновляем вывод каждую секунду
        while time.time() - start_time < args.time:
            sniff(iface=args.interface, prn=handle_packet, monitor=True, timeout=1)
            print_networks()
        
        print_networks()
        print("[*] Сканирование завершено")
    
    except KeyboardInterrupt:
        print("\n[*] Сканирование остановлено пользователем")
    
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        print("[!] Убедитесь, что ваш WiFi адаптер поддерживает режим мониторинга")
        print("[!] И правильно установлены необходимые драйверы (Npcap в Windows)")

if __name__ == "__main__":
    main()
