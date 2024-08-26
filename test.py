from flask import Flask, Response, jsonify, request
from scapy.all import sniff, raw
import threading
import time
import base64

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
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing, filter='udp or esp')

    def packet_callback(self, packet):
        packet_info = {
            'summary': packet.summary(),
            'time': time.time(),
            'hex': base64.b64encode(raw(packet)).decode('utf-8'),
            'layers': self.get_packet_layers(packet)
        }
        self.packets.append(packet_info)

    def get_packet_layers(self, packet):
        layers = []
        while packet:
            layer_name = packet.name
            layer_fields = {}
            for field in packet.fields:
                try:
                    layer_fields[field] = packet.get_field(field).i2repr(packet, getattr(packet, field))
                except:
                    layer_fields[field] = str(getattr(packet, field))
            layers.append({'name': layer_name, 'fields': layer_fields})
            packet = packet.payload if hasattr(packet, 'payload') else None
        return layers

analyzer = PacketAnalyzer()

@app.route('/')
def index():
    return Response('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scapy Web Packet Analyzer</title>
    <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        #app { max-width: 1200px; margin: 0 auto; }
        .packet-list { height: 400px; overflow-y: auto; border: 1px solid #ccc; padding: 10px; }
        .packet-item { cursor: pointer; padding: 5px; border-bottom: 1px solid #eee; }
        .packet-item:hover { background-color: #f0f0f0; }
        .packet-details { margin-top: 20px; border: 1px solid #ccc; padding: 10px; }
        .layer { margin-bottom: 10px; }
        .layer-name { font-weight: bold; }
        .field { margin-left: 20px; }
    </style>
</head>
<body>
    <div id="app">
        <h1>Scapy Web Packet Analyzer</h1>
        <button @click="startSniffing" :disabled="sniffing">Start Sniffing</button>
        <button @click="stopSniffing" :disabled="!sniffing">Stop Sniffing</button>
        <div class="packet-list">
            <div v-for="(packet, index) in packets" :key="index" class="packet-item" @click="showDetails(index)">
                {{ packet.summary }}
            </div>
        </div>
        <div v-if="selectedPacket" class="packet-details">
            <h3>Packet Details:</h3>
            <div v-for="layer in selectedPacket.layers" :key="layer.name" class="layer">
                <div class="layer-name">{{ layer.name }}</div>
                <div v-for="(value, key) in layer.fields" :key="key" class="field">
                    {{ key }}: {{ value }}
                </div>
            </div>
            <h4>Hexdump:</h4>
            <pre>{{ hexdump(selectedPacket.hex) }}</pre>
        </div>
    </div>
    <script>
        new Vue({
            el: '#app',
            data: {
                packets: [],
                sniffing: false,
                selectedPacket: null,
                pollInterval: null
            },
            methods: {
                startSniffing() {
                    axios.post('/start').then(() => {
                        this.sniffing = true;
                        this.pollPackets();
                    });
                },
                stopSniffing() {
                    axios.post('/stop').then(() => {
                        this.sniffing = false;
                        clearInterval(this.pollInterval);
                    });
                },
                pollPackets() {
                    this.pollInterval = setInterval(() => {
                        axios.get(`/packets?start=${this.packets.length}`).then(response => {
                            this.packets.push(...response.data);
                        });
                    }, 1000);
                },
                showDetails(index) {
                    axios.get(`/packet/${index}`).then(response => {
                        this.selectedPacket = response.data;
                    });
                },
                hexdump(hex) {
                    const bytes = atob(hex);
                    let result = '';
                    for (let i = 0; i < bytes.length; i += 16) {
                        let line = bytes.slice(i, i + 16).split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                        result += line.padEnd(48, ' ') + '  ' + bytes.slice(i, i + 16).replace(/[^\x20-\x7E]/g, '.') + '\n';
                    }
                    return result;
                }
            }
        });
    </script>
</body>
</html>
    ''', mimetype='text/html')

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
