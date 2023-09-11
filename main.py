import tkinter as tk
from tkinter import ttk
from scapy.all import IP, TCP, UDP, sniff
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
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

        self.top_ips_label = ttk.Label(root, text="Sending IPs:")
        self.top_ips_label.pack()

        self.top_ips_listbox = tk.Listbox(root, width=80, height=20)
        self.top_ips_listbox.pack()

        self.ip_packets = {}
        self.capture_running = False
        self.sniff_thread = None

    def start(self):
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "active"
        self.save_button["state"] = "disabled"

        interfaces = get_windows_if_list()
        print("Available Interfaces:")
        for iface in interfaces:
            print(f"Name: {iface['name']}, Description: {iface['description']}")

        # Start packet capturing in a separate thread
        self.sniff_thread = threading.Thread(target=self.start_capture)
        self.sniff_thread.start()

    def start_capture(self):
        self.capture_running = True
        sniff(prn=self.process_packet, iface="Ethernet")

    def process_packet(self, pkt):
        if IP in pkt and pkt[IP].src == "192.168.1.80":
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if dst_ip != "192.168.1.80":
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else None
                src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else None

                if dst_port and src_port:
                    packet_info = f"IP: {dst_ip}, Port: {dst_port}"

                    if dst_ip in self.ip_packets:
                        self.ip_packets[dst_ip].add(dst_port)
                    else:
                        self.ip_packets[dst_ip] = {dst_port}

                    self.update_top_ips()
                    self.update_graph()

    def stop(self):
        self.capture_running = False
        self.sniff_thread.join()  # Wait for the capture thread to finish

        self.start_button["state"] = "active"
        self.stop_button["state"] = "disabled"
        self.save_button["state"] = "active"

    def save_info(self):
        # Save info to a file (if needed)
        pass

    def update_top_ips(self):
        self.top_ips_listbox.delete(0, tk.END)
        for ip, ports in self.ip_packets.items():
            for port in ports:
                self.top_ips_listbox.insert(tk.END, f"IP: {ip}, Port: {port}")

    def update_graph(self):
        self.ax.clear()
        ips = list(self.ip_packets.keys())
        port_counts = [len(ports) for ports in self.ip_packets.values()]
        self.ax.bar(ips, port_counts)
        self.canvas.draw()


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzer(root)
    root.mainloop()
