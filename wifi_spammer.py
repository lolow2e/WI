#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WiFi Spammer - Образовательный инструмент для демонстрации создания фейковых WiFi сетей
ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ
"""

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
import os
import random
import time
import argparse

# Список случайных названий сетей
SSID_NAMES = [
    "WiFi_Network_", 
    "HomeNetwork_", 
    "FreeWiFi_", 
    "PublicWiFi_", 
    "GuestNetwork_", 
    "PrivateNet_",
    "TestNet_",
    "Education_",
    "Study_WiFi_"
]

def generate_random_mac():
    """Генерация случайного MAC-адреса"""
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def create_fake_ap(ssid, mac, channel=1, iface="wlan0"):
    """Создание фейковой точки доступа"""
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                 addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap="ESS")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    
    # Добавляем информацию о канале
    channel_info = Dot11Elt(ID="DSset", info=chr(channel))
    
    # Скорость передачи данных
    rates = Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")
    
    # Создаем фрейм
    frame = RadioTap()/dot11/beacon/essid/channel_info/rates
    
    # Отправляем фрейм
    sendp(frame, iface=iface, verbose=0)
    return ssid

def main():
    parser = argparse.ArgumentParser(description='WiFi Spammer - Образовательный инструмент')
    parser.add_argument('-i', '--interface', default="wlan0", help='Сетевой интерфейс')
    parser.add_argument('-n', '--number', type=int, default=10, help='Количество фейковых сетей')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Задержка между отправкой (секунды)')
    args = parser.parse_args()
    
    # Проверяем, запущен ли скрипт с привилегиями администратора
    if os.geteuid() != 0:
        print("Этот скрипт требует привилегий администратора. Запустите с sudo.")
        return
        
    print(f"[*] Начинаем создание {args.number} фейковых WiFi сетей на интерфейсе {args.interface}")
    print("[!] ВНИМАНИЕ: Используйте только в образовательных целях и в контролируемой среде!")
    print("[!] Нажмите Ctrl+C для остановки")
    
    active_networks = []
    
    try:
        while True:
            # Если достигли желаемого количества сетей, обновляем их
            if len(active_networks) >= args.number:
                for i, network in enumerate(active_networks):
                    ssid, mac = network
                    channel = random.randint(1, 11)
                    create_fake_ap(ssid, mac, channel, args.interface)
                    print(f"\r[+] Обновлено {i+1}/{len(active_networks)} фейковых сетей", end="")
                print("\n[*] Все сети обновлены, ожидание...")
            else:
                # Создаем новые сети
                for i in range(args.number - len(active_networks)):
                    prefix = random.choice(SSID_NAMES)
                    ssid = prefix + str(random.randint(100, 999))
                    mac = generate_random_mac()
                    channel = random.randint(1, 11)
                    
                    create_fake_ap(ssid, mac, channel, args.interface)
                    active_networks.append((ssid, mac))
                    print(f"[+] Создана сеть: {ssid} (MAC: {mac}, Канал: {channel})")
            
            time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[*] Остановка создания фейковых сетей...")
        print("[*] Завершено")

if __name__ == "__main__":
    main()
