import tkinter as tk
from scapy.all import IP
from tkinter import ttk
import pandas as pd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import threading

class PacketAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")

        self.start_button = ttk.Button(root, text="Start", command=self.start)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(root, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(pady=10)

        self.save_button = ttk.Button(root, text="Save Info", command=self.save_info, state="disabled")
        self.save_button.pack(pady=10)

        self.fig = Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.top_ips_label = ttk.Label(root, text="Top 5 IPs:")
        self.top_ips_label.pack()

        self.top_ips_listbox = tk.Listbox(root)
        self.top_ips_listbox.pack()

        self.ip_packets = {}

    def start(self):
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "active"
        self.save_button["state"] = "disabled"

        # Print available interfaces
        interfaces = get_windows_if_list()
        print("Available Interfaces:")
        for iface in interfaces:
            print(f"Name: {iface['name']}, Description: {iface['description']}")

        # Start packet capturing in a separate thread
        capture_thread = threading.Thread(target=self.start_capture)
        capture_thread.start()

    def start_capture(self):
        # Update with the correct interface name
        sniff(prn=self.process_packet, iface="Ethernet")  # Update with the correct interface name

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == "192.168.1.80":
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if dst_ip != "192.168.1.80":
                if dst_ip in self.ip_packets:
                    self.ip_packets[dst_ip] += 1
                else:
                    self.ip_packets[dst_ip] = 1

                self.update_top_ips()
                self.update_graph()

    def stop(self):
        self.start_button["state"] = "active"
        self.stop_button["state"] = "disabled"
        self.save_button["state"] = "active"

        # Stop packet capturing (you'll need to implement this)

    def save_info(self):
        df = pd.DataFrame(self.ip_packets.items(), columns=["IP", "Packets"])
        df.to_excel("packet_info.xlsx", index=False)
        print("Info saved to packet_info.xlsx")

    def update_top_ips(self):
        sorted_ips = sorted(self.ip_packets.items(), key=lambda x: x[1], reverse=True)
        self.top_ips_listbox.delete(0, tk.END)
        for ip, count in sorted_ips[:5]:
            self.top_ips_listbox.insert(tk.END, f"{ip}: {count}")

    def update_graph(self):
        self.ax.clear()
        ips = list(self.ip_packets.keys())
        packets = list(self.ip_packets.values())
        self.ax.bar(ips, packets)
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzer(root)
    root.mainloop()