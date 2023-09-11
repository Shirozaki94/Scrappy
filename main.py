from telnetlib import IP
from scapy.all import *
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd

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

        self.ip_packets = {}

    def start(self):
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "active"
        self.save_button["state"] = "disabled"

        # Start packet capturing
        sniff(prn=self.process_packet)

    def process_packet(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            if src_ip in self.ip_packets:
                self.ip_packets[src_ip] += 1
            else:
                self.ip_packets[src_ip] = 1

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
