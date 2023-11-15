import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading
import ipaddress
import socket
import netifaces

def get_local_ip():
    try:
        # Verbindung zu einem externen Server herstellen (z.B., Google DNS)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error:
        return None

def run_ping(ip_address, results, output_widget):
    try:
        result = subprocess.run(["ping", "-n", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        
        if "Minimum" in result.stdout:
            results.append(ip_address)
            output_widget.insert(tk.END, f"IP gefunden: {ip_address}\n")
            
    except subprocess.CalledProcessError:
        pass  # Falls der Ping fehlschlägt, ignorieren wir das

def ping_ip_range(ip_range, output_widget, local_ip):
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
        total_addresses = network.num_addresses

        results = []
        threads = []

        for ip_address in network.hosts():
            ip_address_str = str(ip_address)

            # Überprüfe, ob die IP die lokale IP-Adresse ist, und überspringe sie
            if ip_address_str == local_ip:
                continue

            thread = threading.Thread(target=run_ping, args=(ip_address_str, results, output_widget))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        output_widget.insert(tk.END, f"\nFertig! Gefundene IPs: {len(results)} von {total_addresses}\n")

    except ValueError:
        output_widget.insert(tk.END, "Ungültiges CIDR-Format für den IP-Adressbereich.\n")

def start_pinging(ip_range, output_widget):
    output_widget.delete(1.0, tk.END)  # Lösche vorherige Ausgabe
    local_ip = get_local_ip()
    output_widget.insert(tk.END, f"Lokale IP-Adresse des Rechners: {local_ip}\n")
    output_widget.insert(tk.END, "Suche nach IPs...\n")
    threading.Thread(target=ping_ip_range, args=(ip_range, output_widget, local_ip)).start()

def main():
    root = tk.Tk()
    root.title("IP-Ping-Tool")

    # Eingabefeld für IP-Bereich
    label = tk.Label(root, text="Gib einen IP-Adressbereich im CIDR-Format ein (z. B. 192.168.1.0/24):")
    label.pack(pady=10)

    ip_range_entry = tk.Entry(root, width=30)
    ip_range_entry.pack(pady=10)

    # Textfeld für die Ausgabe
    output_text = scrolledtext.ScrolledText(root, width=50, height=10)
    output_text.pack(pady=10)

    # Button zum Starten des Ping-Prozesses
    start_button = tk.Button(root, text="Start", command=lambda: start_pinging(ip_range_entry.get(), output_text))
    start_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
