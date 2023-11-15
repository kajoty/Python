import tkinter as tk
from tkinter import scrolledtext
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

        # Textfeld für die Ausgabe
        self.output_text = scrolledtext.ScrolledText(root, width=50, height=10)
        self.output_text.pack(pady=10)

        # Button zum Starten des Ping-Prozesses
        start_button = tk.Button(root, text="Start", command=self.start_pinging)
        start_button.pack(pady=10)

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
                self.output_text.insert(tk.END, f"IP gefunden: {ip_address}\n")

        except subprocess.CalledProcessError:
            pass  # Falls der Ping fehlschlägt, ignorieren wir das

    def ping_ip_range(self):
        try:
            network = ipaddress.IPv4Network(self.ip_range_entry.get(), strict=False)
            total_addresses = network.num_addresses

            results = []
            threads = []

            for ip_address in network.hosts():
                ip_address_str = str(ip_address)

                thread = threading.Thread(target=self.run_ping, args=(ip_address_str, results))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # Sortiere die Ergebnisse aufsteigend
            sorted_results = sorted(results, key=lambda ip: ipaddress.IPv4Address(ip))

            self.output_text.insert(tk.END, f"\nFertig! Gefundene IPs: {len(sorted_results)} von {total_addresses}\n")

            for ip_address in sorted_results:
                self.output_text.insert(tk.END, f"IP gefunden: {ip_address}\n")

        except ValueError:
            self.output_text.insert(tk.END, "Ungültiges CIDR-Format für den IP-Adressbereich.\n")

    def start_pinging(self):
        self.output_text.delete(1.0, tk.END)  # Lösche vorherige Ausgabe
        self.ping_ip_range()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
