import tkinter as tk
from tkinter import filedialog
import threading
from scanner import escanear_host

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Vulnerabilidades")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e1e")
        self.setup_ui()

    def setup_ui(self):
        title = tk.Label(self.root, text="Escáner de Puertos y Vulnerabilidades",
                        font=("Arial", 18, "bold"), bg="#1e1e1e", fg="#ffffff")
        title.pack(pady=10)

        frame_ip = tk.Frame(self.root, bg="#1e1e1e")
        frame_ip.pack(pady=5)
        tk.Label(frame_ip, text="Dirección IP:", bg="#1e1e1e", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        self.ip_input = tk.Entry(frame_ip, width=40)
        self.ip_input.pack(side=tk.LEFT, padx=5)

        self.output = tk.Text(self.root, wrap=tk.WORD, bg="#2e2e2e", fg="#ffffff")
        self.output.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        button_frame = tk.Frame(self.root, bg="#1e1e1e")
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Escanear", command=self.run_scan).pack(side=tk.LEFT, padx=10)
        tk.Button(button_frame, text="Guardar Informe", command=self.save_report).pack(side=tk.LEFT, padx=10)

    def run_scan(self):
        ip = self.ip_input.get().strip()
        if not ip:
            self.output.insert(tk.END, "[!] Introduce una IP válida.\n")
            return
        self.output.insert(tk.END, f"[*] Escaneando {ip}...\n\n")
        threading.Thread(target=self.scan_thread, args=(ip,)).start()

    def scan_thread(self, ip):
        resultado = escanear_host(ip)
        if resultado:
            self.output.insert(tk.END, f"[+] Resultados para {ip}:\n")
            self.output.insert(tk.END, str(resultado) + "\n")
        else:
            self.output.insert(tk.END, "[!] No se pudo escanear el host o no está activo.\n")

    def save_report(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Archivos de texto", "*.txt")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.output.get("1.0", tk.END))
                self.output.insert(tk.END, f"[+] Informe guardado en {filename}\n")
            except Exception as e:
                self.output.insert(tk.END, f"[!] Error al guardar informe: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
