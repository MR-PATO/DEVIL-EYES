#!/usr/bin/env python3
import os
import time
import socket
import threading
from scapy.all import ARP, Ether, srp
import netifaces as ni

# Colores ANSI
R = "\033[31m"  # Rojo
G = "\033[32m"  # Verde
Y = "\033[33m"  # Amarillo
B = "\033[34m"  # Azul
C = "\033[36m"  # Cian
W = "\033[0m"   # Blanco/Reset

# Función para obtener la red local automáticamente
def obtener_red_local():
    try:
        interfaz = ni.gateways()['default'][ni.AF_INET][1]
        ip = ni.ifaddresses(interfaz)[ni.AF_INET][0]['addr']
        mascara = ni.ifaddresses(interfaz)[ni.AF_INET][0]['netmask']
        bits = sum([bin(int(x)).count('1') for x in mascara.split('.')])
        return f"{ip}/{bits}"
    except:
        return input(f"{Y}No se detectó red automáticamente. Ingresa la red a escanear (ej. 192.168.1.0/24): {W}")

# Función para escanear dispositivos conectados
def escanear_dispositivos(red):
    print(f"\n{C}[+] Escaneando red {red}...{W}")
    paquetes = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red)
    resultado = srp(paquetes, timeout=2, verbose=0)[0]

    dispositivos = []
    for envio, respuesta in resultado:
        ip = respuesta.psrc
        mac = respuesta.hwsrc
        try:
            nombre = socket.gethostbyaddr(ip)[0]
        except:
            nombre = "Desconocido"
        sistema = detectar_sistema(mac)
        dispositivos.append({'ip': ip, 'mac': mac, 'nombre': nombre, 'so': sistema})

    if dispositivos:
        print(f"\n{G}[✔] Dispositivos encontrados:{W}\n")
        print(f"{B}{'IP':<17} {'MAC':<20} {'NOMBRE':<30} {'SISTEMA':<10}{W}")
        print("-" * 80)
        for d in dispositivos:
            print(f"{d['ip']:<17} {d['mac']:<20} {d['nombre']:<30} {d['so']:<10}")
    else:
        print(f"{R}[!] No se encontraron dispositivos.{W}")

    return dispositivos

# Función para detectar sistema operativo aproximado por MAC
def detectar_sistema(mac):
    if mac.startswith("00:1A:79") or mac.startswith("F4:5C:89"):
        return "Windows"
    elif mac.startswith("D4:F4:6F") or mac.startswith("28:37:37"):
        return "Android"
    elif mac.startswith("3C:07:54") or mac.startswith("F0:18:98"):
        return "Mac"
    elif mac.startswith("7C:D1:C3") or mac.startswith("AC:29:3A"):
        return "iOS"
    else:
        return "Desconocido"

# Escaneo de puertos de un dispositivo
def escanear_puertos(ip):
    print(f"\n{C}[+] Escaneando puertos abiertos en {ip}...{W}")
    puertos_abiertos = []

    def scan_port(port):
        sock = socket.socket()
        sock.settimeout(0.5)
        try:
            sock.connect((ip, port))
            puertos_abiertos.append(port)
        except:
            pass
        sock.close()

    hilos = []
    for puerto in range(1, 1025):
        t = threading.Thread(target=scan_port, args=(puerto,))
        hilos.append(t)
        t.start()

    for t in hilos:
        t.join()

    if puertos_abiertos:
        print(f"{G}[✔] Puertos abiertos en {ip}:{W} {puertos_abiertos}")
    else:
        print(f"{R}[!] No se encontraron puertos abiertos en {ip}.{W}")

# Desautenticación simulada (educativo)
def ataque_desautenticacion(ip, mac):
    print(f"{Y}[!] Función educativa: desautenticando {ip} ({mac})...{W}")
    print(f"{R}[!] Esto requeriría modo monitor y permisos root (uso real con aireplay-ng).{W}")
    time.sleep(2)
    print(f"{G}[✔] Simulación completada.{W}")

# Guardar resultados en archivo
def guardar(dispositivos):
    nombre = f"resultado_escaneo.txt"
    with open(nombre, "w") as f:
        f.write("IP\tMAC\tNOMBRE\tSO\n")
        for d in dispositivos:
            f.write(f"{d['ip']}\t{d['mac']}\t{d['nombre']}\t{d['so']}\n")
    print(f"{G}[✔] Resultados guardados en {nombre}{W}")

# Menú principal
def menu():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print(f"""{B}
╔════════════════════════════════════════════╗
║     ESCÁNER DE RED LOCAL - ETHICAL USE     ║
╠════════════════════════════════════════════╣
║ 1. Escanear dispositivos en la red         ║
║ 2. Escanear puertos de un dispositivo      ║
║ 3. Simular desautenticación (educativo)    ║
║ 4. Salir                                   ║
╚════════════════════════════════════════════╝{W}""")
        opcion = input(f"{C}Seleccione una opción: {W}")

        if opcion == "1":
            red = obtener_red_local()
            dispositivos = escanear_dispositivos(red)
            if dispositivos:
                guardar_op = input(f"{Y}¿Deseas guardar los resultados? (s/n): {W}")
                if guardar_op.lower() == "s":
                    guardar(dispositivos)
            input(f"\n{C}Presiona Enter para continuar...{W}")

        elif opcion == "2":
            ip = input(f"{Y}Ingrese la IP del dispositivo a escanear puertos: {W}")
            escanear_puertos(ip)
            input(f"\n{C}Presiona Enter para continuar...{W}")

        elif opcion == "3":
            ip = input(f"{Y}Ingrese IP del dispositivo a simular desautenticación: {W}")
            mac = input(f"{Y}Ingrese MAC del dispositivo: {W}")
            ataque_desautenticacion(ip, mac)
            input(f"\n{C}Presiona Enter para continuar...{W}")

        elif opcion == "4":
            print(f"{G}Saliendo...{W}")
            break

        else:
            print(f"{R}Opción inválida.{W}")
            time.sleep(1)

# Ejecutar
if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(f"\n{R}Interrumpido por el usuario. Cerrando...{W}")
