# DEVIL-EYES - Escáner de Red y Puertos con Interfaz Avanzada

import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import ARP, Ether, srp
import socket
import threading
import platform
from queue import Queue
from colorama import Fore, init
init(autoreset=True)

# Colores personalizados para fondo oscuro
FONDO = '#121212'
TEXTO = '#E0E0E0'
VERDE = '#00FF00'
ROJO = '#FF5555'

# Configuración de ventana principal
class DevilEyesApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DEVIL-EYES")
        self.root.configure(bg=FONDO)
        self.root.geometry("800x600")

        self.resultados_escaneo = []
        self.resultados_puertos = []

        ttk.Style().theme_use('clam')
        style = ttk.Style()
        style.configure("Treeview", background=FONDO, foreground=TEXTO, fieldbackground=FONDO)
        style.configure("Treeview.Heading", background=FONDO, foreground='white')

        self.crear_widgets()

    def crear_widgets(self):
        frame = tk.Frame(self.root, bg=FONDO)
        frame.pack(pady=20)

        btn_escanear_red = tk.Button(frame, text="Escanear Dispositivos", command=self.escanear_red, bg='#1E88E5', fg='white')
        btn_escanear_red.grid(row=0, column=0, padx=10)

        btn_escanear_puertos = tk.Button(frame, text="Escanear Puertos", command=self.pedir_ip_y_rango, bg='#43A047', fg='white')
        btn_escanear_puertos.grid(row=0, column=1, padx=10)

        btn_ver_abiertos = tk.Button(frame, text="Ver solo Puertos Abiertos", command=self.ver_puertos_abiertos, bg='#FB8C00', fg='white')
        btn_ver_abiertos.grid(row=0, column=2, padx=10)

        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "Nombre", "SO"), show="headings")
        self.tree.heading("IP", text="IP")
        self.tree.heading("MAC", text="MAC")
        self.tree.heading("Nombre", text="Nombre")
        self.tree.heading("SO", text="Sistema Operativo")
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        self.text_result = tk.Text(self.root, bg=FONDO, fg=TEXTO)
        self.text_result.pack(pady=10, fill=tk.BOTH, expand=True)

    def escanear_red(self):
        self.tree.delete(*self.tree.get_children())
        ip_local = self.obtener_ip_local()
        ip_red = '.'.join(ip_local.split('.')[:-1]) + '.1/24'
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_red)
        res, _ = srp(pkt, timeout=2, verbose=0)

        self.resultados_escaneo.clear()

        for _, rcv in res:
            ip = rcv.psrc
            mac = rcv.hwsrc
            try:
                nombre = socket.gethostbyaddr(ip)[0]
            except:
                nombre = "Desconocido"
            so = platform.system()
            self.tree.insert("", "end", values=(ip, mac, nombre, so))
            self.resultados_escaneo.append((ip, mac, nombre, so))

        if messagebox.askyesno("Guardar", "¿Deseas guardar los resultados del escaneo de red?"):
            with open("dispositivos_red.txt", "w") as f:
                for d in self.resultados_escaneo:
                    f.write(f"{d[0]}\t{d[1]}\t{d[2]}\t{d[3]}\n")

    def obtener_ip_local(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def pedir_ip_y_rango(self):
        def iniciar():
            ip = entry_ip.get()
            rango = entry_rango.get()
            try:
                p1, p2 = map(int, rango.split('-'))
                if p1 < 1 or p2 > 65535 or p1 >= p2:
                    raise ValueError
                ventana.destroy()
                self.text_result.delete(1.0, tk.END)
                threading.Thread(target=self.escanear_puertos, args=(ip, p1, p2)).start()
            except:
                messagebox.showerror("Error", "Rango inválido. Ej: 20-100")

        ventana = tk.Toplevel(self.root)
        ventana.title("Escaneo de Puertos")
        ventana.configure(bg=FONDO)

        tk.Label(ventana, text="IP del dispositivo:", bg=FONDO, fg=TEXTO).pack()
        entry_ip = tk.Entry(ventana)
        entry_ip.pack()

        tk.Label(ventana, text="Rango de puertos (Ej: 20-100):", bg=FONDO, fg=TEXTO).pack()
        entry_rango = tk.Entry(ventana)
        entry_rango.pack()

        tk.Button(ventana, text="Iniciar", command=iniciar, bg='#1E88E5', fg='white').pack(pady=10)

    def escanear_puertos(self, ip, start_port, end_port):
        def scan_port(q):
            while not q.empty():
                port = q.get()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                color = VERDE if result == 0 else ROJO
                estado = "ABIERTO" if result == 0 else "CERRADO"
                self.text_result.insert(tk.END, f"Puerto {port}: {estado}\n", ("verde" if result == 0 else "rojo"))
                if result == 0:
                    self.resultados_puertos.append((ip, port))
                sock.close()
                q.task_done()

        self.resultados_puertos.clear()
        self.text_result.tag_config("verde", foreground=VERDE)
        self.text_result.tag_config("rojo", foreground=ROJO)
        self.text_result.insert(tk.END, f"Escaneando {ip} de puerto {start_port} a {end_port}...\n")

        q = Queue()
        for p in range(start_port, end_port + 1):
            q.put(p)

        hilos = []
        for _ in range(100):
            t = threading.Thread(target=scan_port, args=(q,))
            t.start()
            hilos.append(t)

        q.join()

        if messagebox.askyesno("Guardar", "¿Deseas guardar los resultados del escaneo de puertos?"):
            with open("puertos_abiertos.txt", "w") as f:
                for res in self.resultados_puertos:
                    f.write(f"{res[0]}:{res[1]}\n")

    def ver_puertos_abiertos(self):
        self.text_result.delete(1.0, tk.END)
        if not self.resultados_puertos:
            self.text_result.insert(tk.END, "No hay puertos abiertos registrados aún.\n")
        else:
            self.text_result.insert(tk.END, "Puertos abiertos detectados:\n", "verde")
            for res in self.resultados_puertos:
                self.text_result.insert(tk.END, f"{res[0]}:{res[1]}\n", "verde")


if __name__ == "__main__":
    root = tk.Tk()
    app = DevilEyesApp(root)
    root.mainloop()
