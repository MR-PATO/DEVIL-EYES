import scapy.all as scapy
import socket
import os
import netifaces
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog

# Colores para terminal (solo si quieres imprimir en consola)
AZUL = "\033[34m"
ROJO = "\033[31m"
VERDE = "\033[32m"
NARANJA = "\033[33m"
RESET = "\033[0m"

# Funciones básicas

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

# Escaneo de red con scapy

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

# Mostrar resultados en tabla con ventana gráfica

def mostrar_resultados_en_tabla(dispositivos):
    ventana = tk.Toplevel()
    ventana.title("Dispositivos en la red")
    ventana.configure(bg="#1e1e1e")
    ventana.geometry("720x400")

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

# Escaneo de puertos con ventana y hilos

def obtener_velocidad_gui():
    ventana = tk.Tk()
    ventana.title("Seleccionar velocidad de escaneo")
    ventana.geometry("300x180")
    ventana.configure(bg="#1e1e1e")

    var = tk.StringVar(value="2")

    opciones = {
        "1 - Lento (2 seg)": 2,
        "2 - Rápido (0.5 seg)": 0.5,
        "3 - Súper rápido (0.1 seg)": 0.1,
        "4 - Ultra rápido (0.01 seg)": 0.01,
    }

    def seleccionar():
        ventana.destroy()

    tk.Label(ventana, text="Seleccione la velocidad de escaneo:", fg="#00ffcc",
             bg="#1e1e1e", font=("Consolas", 11)).pack(pady=10)

    for texto, val in opciones.items():
        rb = tk.Radiobutton(ventana, text=texto, variable=var, value=str(val),
                            fg="white", bg="#1e1e1e", selectcolor="#007acc", font=("Consolas", 10))
        rb.pack(anchor="w", padx=20)

    tk.Button(ventana, text="Confirmar", command=seleccionar,
              bg="#007acc", fg="white", font=("Consolas", 11, "bold")).pack(pady=10)

    ventana.mainloop()

    return float(var.get())

def escanear_puertos(ip, nombre, mostrar_en_ventana=True):
    timeout = obtener_velocidad_gui()
    resultados = []

    def escanear_puerto(puerto):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((ip, puerto))
        if resultado == 0:
            resultados.append(puerto)
        sock.close()

    hilos = []
    for puerto in range(1, 1025):  # Puedes cambiar a 65536 si quieres más puertos
        hilo = threading.Thread(target=escanear_puerto, args=(puerto,))
        hilos.append(hilo)
        hilo.start()

    for hilo in hilos:
        hilo.join()

    if mostrar_en_ventana:
        ventana = tk.Toplevel()
        ventana.title(f"Puertos abiertos en {ip} ({nombre})")
        ventana.geometry("400x300")
        ventana.configure(bg="#1e1e1e")

        texto_scroll = scrolledtext.ScrolledText(ventana, width=50, height=15,
                                                 bg="#2e2e2e", fg="#dcdcdc", font=("Consolas", 11))
        texto_scroll.pack(padx=10, pady=10)

        if resultados:
            for puerto in sorted(resultados):
                texto_scroll.insert(tk.END, f"Puerto {puerto} ABIERTO\n")
        else:
            texto_scroll.insert(tk.END, "No se encontraron puertos abiertos.\n")

        texto_scroll.config(state=tk.DISABLED)

        def guardar():
            if not resultados:
                messagebox.showinfo("Guardar", "No hay datos para guardar.")
                return
            guardar_archivo = messagebox.askyesno("Guardar", "¿Deseas guardar los resultados en un archivo?")
            if guardar_archivo:
                archivo = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Texto", "*.txt"), ("CSV", "*.csv")]
                )
                if archivo:
                    with open(archivo, "w") as f:
                        for puerto in sorted(resultados):
                            f.write(f"Puerto {puerto} ABIERTO\n")
                    messagebox.showinfo("Guardado", f"Datos guardados en:\n{archivo}")

        boton_guardar = tk.Button(ventana, text="Guardar resultados", command=guardar,
                                  bg="#007acc", fg="white", font=("Consolas", 11, "bold"))
        boton_guardar.pack(pady=10)

        ventana.mainloop()

    else:
        # Solo mostrar en consola (opcional)
        for puerto in sorted(resultados):
            print(f"{VERDE}Puerto {puerto} ABIERTO{RESET}")

# Ventana principal - menú

def ventana_menu():
    ip_local = obtener_ip_local()
    if not ip_local:
        messagebox.showerror("Error", "No se pudo determinar la IP local. Asegúrate de estar conectado a una red.")
        return

    dispositivos = []

    root = tk.Tk()
    root.title("MR.Pato Scanner v1.5")
    root.geometry("600x400")
    root.configure(bg="#1e1e1e")

    titulo = tk.Label(root, text="MR.Pato Scanner v1.5", font=("Consolas", 20, "bold"),
                      fg="#00ffcc", bg="#1e1e1e")
    titulo.pack(pady=20)

    info_ip = tk.Label(root, text=f"IP Local detectada: {ip_local}", font=("Consolas", 12),
                       fg="white", bg="#1e1e1e")
    info_ip.pack(pady=5)

    def boton_escaneo_red():
        nonlocal dispositivos
        dispositivos = escanear_red(".".join(ip_local.split(".")[:-1]))
        if dispositivos:
            mostrar_resultados_en_tabla(dispositivos)
        else:
            messagebox.showinfo("Sin resultados", "No se encontraron dispositivos en la red.")

    def boton_escaneo_puertos_todos():
        if not dispositivos:
            messagebox.showwarning("Atención", "Primero escanee la red para detectar dispositivos.")
            return
        for d in dispositivos:
            escanear_puertos(d["ip"], d["nombre"])

    def boton_escaneo_puertos_ip():
        ip_obj = simpledialog.askstring("Escanear IP", "Ingrese la IP que desea escanear:")
        if not ip_obj:
            return
        nombre_obj = obtener_nombre(ip_obj)
        escanear_puertos(ip_obj, nombre_obj)

    def salir():
        root.destroy()

    btn1 = tk.Button(root, text="1. Escanear dispositivos en la red", font=("Consolas", 12),
                     bg="#007acc", fg="white", command=boton_escaneo_red)
    btn1.pack(pady=10, fill="x", padx=50)

    btn2 = tk.Button(root, text="2. Escanear puertos abiertos en dispositivos detectados", font=("Consolas", 12),
                     bg="#007acc", fg="white", command=boton_escaneo_puertos_todos)
    btn2.pack(pady=10, fill="x", padx=50)

    btn3 = tk.Button(root, text="3. Escanear puertos en una IP específica", font=("Consolas", 12),
                     bg="#007acc", fg="white", command=boton_escaneo_puertos_ip)
    btn3.pack(pady=10, fill="x", padx=50)

    btn4 = tk.Button(root, text="4. Salir", font=("Consolas", 12),
                     bg="#cc3300", fg="white", command=salir)
    btn4.pack(pady=10, fill="x", padx=50)

    root.mainloop()

if __name__ == "__main__":
    ventana_menu()
