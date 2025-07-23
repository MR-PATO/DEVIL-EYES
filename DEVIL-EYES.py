import os
import socket
import platform
from scapy.all import ARP, Ether, srp
import threading
from queue import Queue
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from colorama import Fore, Style, init
import time

init(autoreset=True)

# --- Escaneo de dispositivos en red ---

def obtener_dispositivos(red):
    dispositivos = []
    paquete_arp = ARP(pdst=red)
    paquete_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = paquete_ether / paquete_arp

    resultado = srp(paquete, timeout=3, verbose=0)[0]

    for envio, recibido in resultado:
        ip = recibido.psrc
        mac = recibido.hwsrc
        try:
            nombre = socket.gethostbyaddr(ip)[0]
        except:
            nombre = "Desconocido"

        try:
            so = platform.system()
        except:
            so = "Desconocido"

        dispositivos.append((ip, mac, nombre, so))
    return dispositivos

def mostrar_ventana_dispositivos(dispositivos):
    ventana = tk.Tk()
    ventana.title("DEVIL-EYES - Dispositivos en Red")
    ventana.configure(bg="#121212")
    ventana.geometry("900x400")

    style = ttk.Style(ventana)
    style.theme_use("clam")
    style.configure("Treeview", 
                    background="#1e1e1e", 
                    foreground="white", 
                    fieldbackground="#1e1e1e", 
                    rowheight=25)
    style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

    tabla = ttk.Treeview(ventana, columns=("IP", "MAC", "Nombre", "SO"), show="headings")
    tabla.heading("IP", text="IP")
    tabla.heading("MAC", text="MAC")
    tabla.heading("Nombre", text="Nombre")
    tabla.heading("SO", text="Sistema Operativo")

    for dispositivo in dispositivos:
        tabla.insert("", "end", values=dispositivo)

    tabla.pack(padx=10, pady=10, fill="both", expand=True)

    scrollbar = ttk.Scrollbar(ventana, orient="vertical", command=tabla.yview)
    tabla.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    ventana.mainloop()

# --- Escaneo de puertos multi-hilo ---

def escanear_puerto(ip, puerto, resultados, mostrar_cerrados):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            print(f"{Fore.GREEN}🟢 Puerto {puerto} ABIERTO en {ip}{Style.RESET_ALL}")
            resultados.append(puerto)
        else:
            if mostrar_cerrados:
                print(f"{Fore.RED}🔴 Puerto {puerto} CERRADO en {ip}{Style.RESET_ALL}")
    except Exception:
        pass
    finally:
        sock.close()

def worker(ip, queue, resultados, mostrar_cerrados):
    while not queue.empty():
        puerto = queue.get()
        escanear_puerto(ip, puerto, resultados, mostrar_cerrados)
        queue.task_done()

def escaneo_multihilo(ip, inicio=1, fin=1024, mostrar_cerrados=True, solo_abiertos=False, hilos=100):
    print(f"\nIniciando escaneo multi-hilo en {ip} puertos {inicio}-{fin}...\n")
    queue = Queue()
    resultados = []

    for puerto in range(inicio, fin+1):
        queue.put(puerto)

    threads = []
    for _ in range(hilos):
        t = threading.Thread(target=worker, args=(ip, queue, resultados, mostrar_cerrados))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    print("\nEscaneo finalizado.\n")

    if resultados:
        guardar = input("¿Deseas guardar los puertos abiertos en un archivo? (s/n): ").lower()
        if guardar == "s":
            archivo = f"puertos_abiertos_{ip.replace('.', '_')}.txt"
            with open(archivo, "w") as f:
                for puerto in resultados:
                    f.write(f"Puerto {puerto} ABIERTO en {ip}\n")
            print(f"{Fore.YELLOW}✅ Puertos abiertos guardados en {archivo}{Style.RESET_ALL}")
    else:
        print("No se encontraron puertos abiertos.")

# --- Obtener IP local para red ---

def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

# --- Menú principal ---

def menu():
    while True:
        print(f"""
{Fore.RED}██████╗ ███████╗██╗   ██╗██╗██╗     
██╔══██╗██╔════╝██║   ██║██║██║     
██║  ██║█████╗  ██║   ██║██║██║     
██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     
██████╔╝███████╗ ╚████╔╝ ██║███████╗
╚═════╝ ╚══════╝  ╚═══╝  ╚═╝╚══════╝
{Style.RESET_ALL}
{Fore.CYAN}[1]{Style.RESET_ALL} Escanear dispositivos conectados
{Fore.CYAN}[2]{Style.RESET_ALL} Escanear todos los puertos de una IP
{Fore.CYAN}[3]{Style.RESET_ALL} Ver únicamente puertos abiertos
{Fore.CYAN}[4]{Style.RESET_ALL} Salir
""")

        opcion = input("Selecciona una opción: ")

        if opcion == "1":
            ip_local = obtener_ip_local()
            if ip_local:
                red = ip_local.rsplit('.', 1)[0] + ".1/24"
                print(f"Escaneando red: {red} ...")
                dispositivos = obtener_dispositivos(red)
                mostrar_ventana_dispositivos(dispositivos)
                guardar = input("¿Deseas guardar los dispositivos encontrados en un archivo? (s/n): ").lower()
                if guardar == "s":
                    with open("dispositivos.txt", "w") as f:
                        for d in dispositivos:
                            f.write(f"{d[0]}\t{d[1]}\t{d[2]}\t{d[3]}\n")
                    print(f"{Fore.YELLOW}✅ Resultados guardados en dispositivos.txt")
            else:
                print("No se pudo obtener la IP local.")

        elif opcion == "2":
            ip = input("Ingresa la IP a escanear: ")
            escaneo_multihilo(ip, 1, 1024, mostrar_cerrados=True, solo_abiertos=False)

        elif opcion == "3":
            ip = input("Ingresa la IP a escanear: ")
            escaneo_multihilo(ip, 1, 1024, mostrar_cerrados=False, solo_abiertos=True)

        elif opcion == "4":
            print("¡Hasta luego!")
            break

        else:
            print("Opción no válida.")

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    menu()
