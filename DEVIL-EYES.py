import scapy.all as scapy
import socket
import os
import netifaces
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk

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

def detectar_sistema(nombre):
    nombre_lower = nombre.lower()
    if "android" in nombre_lower:
        return "Android"
    elif "win" in nombre_lower or "windows" in nombre_lower:
        return "Windows"
    elif "mac" in nombre_lower or "apple" in nombre_lower:
        return "macOS/iOS"
    elif "iphone" in nombre_lower or "ios" in nombre_lower:
        return "iOS"
    else:
        return "Desconocido"

def escanear_red(ip):
    request = scapy.ARP(pdst=f"{ip}/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    respuesta = scapy.srp(broadcast / request, timeout=2, verbose=False)[0]

    dispositivos = []
    for _, recibido in respuesta:
        ip_dispositivo = recibido.psrc
        mac_dispositivo = recibido.hwsrc
        nombre = obtener_nombre(ip_dispositivo)
        dispositivos.append({
            "ip": ip_dispositivo,
            "nombre": nombre,
            "mac": mac_dispositivo,
            "so": detectar_sistema(nombre)
        })

    return dispositivos

def mostrar_resultados_en_tabla(dispositivos):
    ventana = tk.Tk()
    ventana.title("Dispositivos en la red")
    ventana.configure(bg="#1e1e1e")

    style = ttk.Style(ventana)
    style.theme_use("default")
    style.configure("Treeview",
                    background="#2e2e2e",
                    foreground="white",
                    rowheight=25,
                    fieldbackground="#2e2e2e",
                    font=("Consolas", 10))
    style.map("Treeview", background=[("selected", "#007acc")])

    titulo = tk.Label(ventana, text="Dispositivos Detectados (IP - MAC - Nombre - Sistema)",
                      bg="#1e1e1e", fg="#00ffcc", font=("Consolas", 14, "bold"))
    titulo.pack(pady=10)

    columnas = ("ip", "mac", "nombre", "so")
    tabla = ttk.Treeview(ventana, columns=columnas, show="headings")
    for col in columnas:
        tabla.heading(col, text=col.upper())
        tabla.column(col, width=160 if col != "nombre" else 240)

    scrollbar = ttk.Scrollbar(ventana, orient="vertical", command=tabla.yview)
    tabla.configure(yscroll=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    tabla.pack(padx=10, pady=10, fill="both", expand=True)

    for d in dispositivos:
        tabla.insert("", tk.END, values=(d['ip'], d['mac'], d['nombre'], d['so']))

    def guardar():
        if not dispositivos:
            messagebox.showinfo("Guardar", "No hay datos para guardar.")
            return
        guardar_archivo = messagebox.askyesno("Guardar", "¿Deseas guardar los resultados en un archivo?")
        if guardar_archivo:
            archivo = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv"), ("Texto", "*.txt")]
            )
            if archivo:
                with open(archivo, "w") as f:
                    f.write("IP,MAC,Nombre,Sistema\n")
                    for d in dispositivos:
                        f.write(f"{d['ip']},{d['mac']},{d['nombre']},{d['so']}\n")
                messagebox.showinfo("Guardado", f"Datos guardados en:\n{archivo}")

    boton_guardar = tk.Button(ventana, text="Guardar resultados", command=guardar,
                               bg="#007acc", fg="white", font=("Consolas", 11, "bold"))
    boton_guardar.pack(pady=10)

    ventana.mainloop()

def obtener_velocidad():
    velocidades = {"1": 2, "2": 0.5, "3": 0.1, "4": 0.01}
    ventana = tk.Tk()
    ventana.withdraw()
    seleccion = tk.simpledialog.askstring("Velocidad", "Seleccione la velocidad (1-lenta, 2-rápida, 3-súper rápida, 4-ultra):")
    ventana.destroy()
    return velocidades.get(seleccion, 0.5)

def escanear_puertos(ip, nombre):
    timeout = obtener_velocidad()
    print(f"\nEscaneando puertos en {ip} ({nombre})...\n")

    def escanear_puerto(puerto):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            print(f"{VERDE}{puerto} ABIERTO {ip} {nombre}{RESET}")
        sock.close()

    hilos = []
    for puerto in range(1, 1025):
        hilo = threading.Thread(target=escanear_puerto, args=(puerto,))
        hilos.append(hilo)
        hilo.start()

    for hilo in hilos:
        hilo.join()

def menu_grafico():
    ip_local = obtener_ip_local()
    if not ip_local:
        messagebox.showerror("Error", "No se pudo determinar la IP local.")
        return

    dispositivos = escanear_red(ip_local)
    if dispositivos:
        mostrar_resultados_en_tabla(dispositivos)
    else:
        messagebox.showinfo("Sin resultados", "No se encontraron dispositivos en la red.")

if __name__ == "__main__":
    menu_grafico()
