import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff
import threading
import json

class PacketAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("Scapy Interactive Packet Analyzer")
        master.geometry("1000x600")

        self.packets = []
        self.create_widgets()
        self.sniffer_thread = None
        self.sniffing = False

    def create_widgets(self):
        # Create a frame for controls
        control_frame = ttk.Frame(self.master)
        control_frame.pack(padx=10, pady=10, fill=tk.X)

        # Start button
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Stop button
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Create a frame for the packet list and details
        content_frame = ttk.Frame(self.master)
        content_frame.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)

        # Create a treeview for the packet list
        self.packet_tree = ttk.Treeview(content_frame, columns=('No.', 'Summary'), show='headings')
        self.packet_tree.heading('No.', text='No.')
        self.packet_tree.heading('Summary', text='Summary')
        self.packet_tree.column('No.', width=50)
        self.packet_tree.column('Summary', width=400)
        self.packet_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        # Bind the treeview selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

        # Create a scrolled text widget for packet details
        self.details_area = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, width=50)
        self.details_area.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

    def packet_callback(self, packet):
        self.packets.append(packet)
        summary = packet.summary()
        self.master.after(0, self.update_packet_list, len(self.packets), summary)

    def update_packet_list(self, index, summary):
        self.packet_tree.insert('', 'end', values=(index, summary))

    def on_packet_select(self, event):
        selected_item = self.packet_tree.selection()[0]
        packet_index = int(self.packet_tree.item(selected_item)['values'][0]) - 1
        packet = self.packets[packet_index]
        self.show_packet_details(packet)

    def show_packet_details(self, packet):
        self.details_area.delete(1.0, tk.END)
        details = self.packet_to_dict(packet)
        self.details_area.insert(tk.END, json.dumps(details, indent=2))

    def packet_to_dict(self, packet):
        return {
            layer.name: {
                field.name: field.value for field in layer.fields_desc
                if hasattr(layer, field.name)
            } for layer in packet.layers()
        }

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzer(root)
    root.mainloop()
