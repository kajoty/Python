import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox
import subprocess
import threading
import ipaddress
import socket

class PingApp:
    def __init__(self, root):
        self.root = root
        root.title("IP-Ping-Tool")

        # Label für lokale IP
        self.local_ip_label = tk.Label(root, text="")
        self.local_ip_label.pack(pady=10)

        # Anzeige der lokalen IP vor dem Drücken des Start-Buttons
        self.get_local_ip()

        # Eingabefeld für IP-Bereich
        label = tk.Label(root, text="Gib einen IP-Adressbereich im CIDR-Format ein (z. B. 192.168.1.0/24):")
        label.pack(pady=10)

        self.ip_range_entry = tk.Entry(root, width=30)
        self.ip_range_entry.pack(pady=10)

        # Eingabefelder für Portbereich
        self.port_from_label = tk.Label(root, text="Port von:")
        self.port_from_label.pack(pady=5)
        self.port_from_entry = tk.Entry(root, width=10)
        self.port_from_entry.pack(pady=5)

        self.port_to_label = tk.Label(root, text="Port bis:")
        self.port_to_label.pack(pady=5)
        self.port_to_entry = tk.Entry(root, width=10)
        self.port_to_entry.pack(pady=10)

        # Textfeld für die Ausgabe
        self.output_text = scrolledtext.ScrolledText(root, width=50, height=10)
        self.output_text.pack(pady=10)

        # Label für die "Bitte warten"-Nachricht
        self.wait_label = tk.Label(root, text="")
        self.wait_label.pack(pady=10)

        # Fortschrittsbalken für den Portscan
        self.progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")

        self.progress_bar.pack(pady=10)

        # Button zum Starten des Ping-Prozesses
        start_button = tk.Button(root, text="Start", command=self.start_pinging)
        start_button.pack(pady=10)

        # Button für Portscan
        scan_button = tk.Button(root, text="Portscan für ausgewählte IP", command=self.start_port_scan)
        scan_button.pack(pady=10)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            self.local_ip_label.config(text=f"Lokale IP-Adresse des Rechners: {local_ip}")
        except socket.error:
            self.local_ip_label.config(text="Konnte die lokale IP-Adresse nicht abrufen.")

    def run_ping(self, ip_address, results):
        try:
            result = subprocess.run(["ping", "-n", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')

            if "Minimum" in result.stdout and ip_address != self.local_ip_label.cget("text").split(":")[1].strip():
                results.append(ip_address)

        except subprocess.CalledProcessError:
            pass  # Falls der Ping fehlschlägt, ignorieren wir das

    def ping_ip_range(self):
        try:
            network = ipaddress.IPv4Network(self.ip_range_entry.get(), strict=False)
            total_addresses = network.num_addresses

            results = []
            threads = []

            # Ändere die Nachricht im "Bitte warten"-Label
            self.wait_label.config(text="Bitte warten. Suche läuft.")

            for ip_address in network.hosts():
                ip_address_str = str(ip_address)

                thread = threading.Thread(target=self.run_ping, args=(ip_address_str, results))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # Sortiere die Ergebnisse aufsteigend
            sorted_results = sorted(results, key=lambda ip: ipaddress.IPv4Address(ip))

            # Lösche vorherige Ausgabe
            self.output_text.delete(1.0, tk.END)

            for ip_address in sorted_results:
                self.output_text.insert(tk.END, f"IP gefunden: {ip_address}\n")

            self.output_text.insert(tk.END, f"\nFertig! Gefundene IPs: {len(sorted_results)} von {total_addresses}\n")

        except ValueError:
            self.output_text.insert(tk.END, "Ungültiges CIDR-Format für den IP-Adressbereich.\n")

        finally:
            # Ändere die Nachricht im "Bitte warten"-Label zurück
            self.wait_label.config(text="")

    def start_pinging(self):
        threading.Thread(target=self.ping_ip_range).start()

    def start_port_scan(self):
        selected_ip = simpledialog.askstring("IP-Auswahl", "Geben Sie die IP-Adresse ein:")
        if not selected_ip:
            return

        try:
            port_from = int(self.port_from_entry.get())
            port_to = int(self.port_to_entry.get())

            # Führe den Portscan durch
            self.output_text.delete(1.0, tk.END)
            threading.Thread(target=self.port_scan, args=(selected_ip, range(port_from, port_to + 1))).start()

        except ValueError:
            messagebox.showerror("Fehler", "Ungültige Portnummer.")

    def port_scan(self, ip_address, ports):
        open_ports = []

        # Setze Fortschrittsbalken-Parameter
        self.progress_bar["maximum"] = len(ports)
        self.progress_bar["value"] = 0

        for i, port in enumerate(ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))

            if result == 0:
                open_ports.append(port)

            sock.close()

            # Aktualisiere Fortschrittsbalken
            self.progress_bar["value"] = i + 1
            self.root.update_idletasks()

        # Zeige das Ergebnis in der Ausgabe an
        self.output_text.insert(tk.END, f"\nPortscan für IP {ip_address}:\n")

        if open_ports:
            self.output_text.insert(tk.END, f"Offene Ports: {', '.join(map(str, open_ports))}\n")
        else:
            self.output_text.insert(tk.END, "Keine offenen Ports gefunden.\n")

        self.output_text.insert(tk.END, f"\nPortscan für IP {ip_address} abgeschlossen.\n")

        # Infofenster anzeigen
        messagebox.showinfo("Portscan Ergebnis", f"Portscan abgeschlossen für IP {ip_address}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
