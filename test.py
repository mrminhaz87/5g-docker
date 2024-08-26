from flask import Flask, render_template, jsonify, request
from scapy.all import sniff
import threading
import time

app = Flask(__name__)

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.sniffing = False
        self.sniffer_thread = None

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.sniffer_thread.join()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing)

    def packet_callback(self, packet):
        packet_info = {
            'summary': packet.summary(),
            'time': time.time(),
            'details': self.packet_to_dict(packet)
        }
        self.packets.append(packet_info)

    def packet_to_dict(self, packet):
        return {
            layer.name: {
                field.name: str(getattr(layer, field.name))
                for field in layer.fields_desc
                if hasattr(layer, field.name)
            } for layer in packet.layers()
        }

analyzer = PacketAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    analyzer.start_sniffing()
    return jsonify({"status": "started"})

@app.route('/stop', methods=['POST'])
def stop():
    analyzer.stop_sniffing()
    return jsonify({"status": "stopped"})

@app.route('/packets')
def get_packets():
    start = int(request.args.get('start', 0))
    end = int(request.args.get('end', len(analyzer.packets)))
    return jsonify(analyzer.packets[start:end])

@app.route('/packet/<int:packet_id>')
def get_packet(packet_id):
    if 0 <= packet_id < len(analyzer.packets):
        return jsonify(analyzer.packets[packet_id])
    else:
        return jsonify({"error": "Packet not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
