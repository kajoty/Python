import tkinter as tk
from tkinter import scrolledtext
import subprocess
import concurrent.futures
import ipaddress
import socket
import threading

class PingApp:
    def __init__(self, root):
        self.root = root
        root.title("IP-Ping-Tool")

        # Variable für die IP-Adresse im CIDR-Format
        self.ip_range_var = tk.StringVar()

        # Label für lokale IP
        self.local_ip_label = tk.Label(root, text="")
        self.local_ip_label.pack(pady=10)

        # Anzeige der lokalen IP vor dem Drücken des Start-Buttons
        self.get_local_ip()

        # Eingabefeld für IP-Bereich
        label = tk.Label(root, text="Gib einen IP-Adressbereich im CIDR-Format ein (z. B. 192.168.1.0/24):")
        label.pack(pady=10)

        self.ip_range_entry = tk.Entry(root, width=30, textvariable=self.ip_range_var)
        self.ip_range_entry.pack(pady=10)

        # Textfeld für die Ausgabe
        self.output_text = scrolledtext.ScrolledText(root, width=50, height=10)
        self.output_text.pack(pady=10)

        # Label für die "Bitte warten"-Nachricht
        self.wait_label = tk.Label(root, text="")
        self.wait_label.pack(pady=10)

        # Button zum Starten des Ping-Prozesses
        self.start_button = tk.Button(root, text="Start", command=self.start_pinging)
        self.start_button.pack(pady=10)

        # Button zum Stoppen des Ping-Prozesses
        self.stop_button = tk.Button(root, text="Stop", command=self.stop_pinging, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Variable für den Status der Suche
        self.searching = False

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Setze die lokale IP als Vorauswahl im Eingabefeld
            self.local_ip_label.config(text=f"Lokale IP-Adresse des Rechners: {local_ip}")
            self.ip_range_var.set(f"{local_ip}/24")

        except socket.error:
            self.local_ip_label.config(text="Konnte die lokale IP-Adresse nicht abrufen.")

    def run_ping(self, ip_address):
        try:
            # Setze das Timeout auf 500 Millisekunden
            result = subprocess.run(["ping", "-n", "1", "-w", "500", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')

            if "Minimum" in result.stdout and ip_address != self.local_ip_label.cget("text").split(":")[1].strip():
                return f"IP gefunden: {ip_address}"

        except subprocess.CalledProcessError:
            pass  # Falls der Ping fehlschlägt, ignorieren wir das

    def ping_ip_range(self):
        try:
            network = ipaddress.IPv4Network(self.ip_range_var.get(), strict=False)

            # Ändere die Nachricht im "Bitte warten"-Label
            self.wait_label.config(text="Bitte warten. Suche läuft.")

            self.start_button.config(state=tk.DISABLED)  # Deaktiviere Start-Button
            self.stop_button.config(state=tk.NORMAL)  # Aktiviere Stop-Button
            self.searching = True

            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Ping für jede IP in einem separaten Thread ausführen
                results = list(executor.map(self.run_ping, map(str, network.hosts())))

            # Filtere die Ergebnisse und entferne None-Werte
            results = list(filter(None, results))

            # Sortiere die Ergebnisse aufsteigend
            sorted_results = sorted(results, key=lambda ip: ipaddress.IPv4Address(ip.split(":")[1].strip()))

            # Lösche vorherige Ausgabe
            self.output_text.delete(1.0, tk.END)

            for result in sorted_results:
                self.output_text.insert(tk.END, f"{result}\n")

            total_addresses = sum(1 for _ in network.hosts())
            self.output_text.insert(tk.END, f"\nFertig! Gefundene IPs: {len(sorted_results)} von {total_addresses}\n")

        except ValueError:
            self.output_text.insert(tk.END, "Ungültiges CIDR-Format für den IP-Adressbereich.\n")

        finally:
            # Ändere die Nachricht im "Bitte warten"-Label zurück
            self.wait_label.config(text="")
            # Aktualisiere die Buttons
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.searching = False

    def start_pinging(self):
        threading.Thread(target=self.ping_ip_range).start()

    def stop_pinging(self):
        self.searching = False

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
