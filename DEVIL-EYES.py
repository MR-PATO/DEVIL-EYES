#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import subprocess
import platform
from datetime import datetime

try:
    import nmap
except ImportError:
    print("\n[!] Módulo 'nmap' no encontrado. Ejecuta: pip3 install python-nmap\n")
    sys.exit(1)

"""
   ____              __            _       _       
  |  _ \  __ _ _ __ / _| ___ _ __ | |_ ___| |_ ___ 
  | | | |/ _` | '_ \ |_ / _ \ '_ \| __/ _ \ __/ __|
  | |_| | (_| | | | |  _|  __/ | | | ||  __/ |_\__ \
  |____/ \__,_|_| |_|_|  \___|_| |_|\__\___|\__|___/
  
  Autor: mamichan v1.0
  Compatible con Termux y Kali Linux
"""

def print_banner():
    banner = r"""
     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   
     █       █       █  █ █  █       █   ▄  █  
     █   ▄   █    ▄▄▄█  █ █  █    ▄▄▄█  █ █ █  
     █  █ █  █   █▄▄▄█  █▄█  █   █▄▄▄█   █▄▄█▄ 
     █  █▄█  █    ▄▄▄█       █    ▄▄▄█    ▄  █ 
     █       █   █   █       █   █   █   █  █ █ 
     █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄█  █▄█ 
    """
    print(banner)
    print("  Autor: mamichan v1.0 | Kali & Termux")
    print("  [DEVOLVER DIED NETWORK KICKER]")
    print("═" * 60)

def check_root():
    if os.geteuid() != 0:
        print("\n[!] Ejecuta como root para mejor funcionalidad")
        print("Ejemplo: sudo python3 kick.py\n")
        return False
    return True

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"[!] Error obteniendo IP local: {str(e)}")
        return "127.0.0.1"

def scan_network():
    nm = nmap.PortScanner()
    ip_range = f"{get_local_ip()}/24"

    print("\n[+] Escaneando red local...")
    try:
        nm.scan(hosts=ip_range, arguments='-sn -T4')
        devices = []

        for host in nm.all_hosts():
            mac = 'Desconocido'
            vendor = ''
            if 'mac' in nm[host].get('addresses', {}):
                mac = nm[host]['addresses']['mac']
                vendor = nm[host].get('vendor', {}).get(mac, 'Desconocido')
            hostname = nm[host].hostname() or 'Desconocido'

            devices.append({
                'ip': host,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor
            })

        return devices
    except Exception as e:
        print(f"[!] Error en escaneo: {str(e)}")
        return []

def display_devices(devices):
    print("\n[+] Dispositivos encontrados:")
    print("-" * 85)
    print("Nr\tIP\t\tMAC\t\t\tHostname\t\tFabricante")
    print("-" * 85)

    for idx, device in enumerate(devices):
        print(f"{idx + 1}\t{device['ip']}\t{device['mac']}\t{device['hostname'][:15]}\t\t{device['vendor'][:20]}")

def block_device(ip):
    try:
        print(f"\n[+] Intentando bloquear IP: {ip}")
        system = platform.system()

        if "Linux" in system:
            if shutil.which("iptables"):
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                print(f"[✓] IP {ip} bloqueada con iptables")
            elif shutil.which("nft"):
                os.system(f"nft add rule ip filter INPUT ip saddr {ip} counter drop")
                print(f"[✓] IP {ip} bloqueada con nftables")
            else:
                print("[!] No se encontró iptables ni nftables")

            if os.path.exists("/etc/init.d/netfilter-persistent"):
                os.system("netfilter-persistent save")
                print("[+] Reglas guardadas permanentemente")

        print(f"[✓] Dispositivo {ip} bloqueado")
    except Exception as e:
        print(f"[!] Error al bloquear IP: {str(e)}")

def main():
    print_banner()

    if not check_root():
        print("[!] Algunas funciones pueden estar limitadas")

    devices = scan_network()

    if not devices:
        print("\n[!] No se encontraron dispositivos en la red")
        sys.exit(1)

    display_devices(devices)

    try:
        choice = int(input("\n[?] Seleccione dispositivo a bloquear (Nr) o 0 para salir: "))
        if choice == 0:
            print("\n[!] Saliendo...")
            sys.exit(0)

        selected = devices[choice - 1]
        print(f"\n[!] Preparando para bloquear: {selected['ip']} ({selected['hostname']})")
        confirm = input("[?] ¿Estás seguro? (s/n): ").lower()

        if confirm == 's':
            block_device(selected['ip'])
        else:
            print("[!] Operación cancelada")
    except (ValueError, IndexError):
        print("\n[!] Selección inválida")
        sys.exit(1)

if __name__ == "__main__":
    try:
        import shutil
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupción por usuario")
        sys.exit(0)
