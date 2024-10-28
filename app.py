from flask import Flask, render_template, jsonify
from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import json
from datetime import datetime

app = Flask(__name__)

# Global variables to store packets and the capturing state
packets = []
capturing = False
capture_thread = None  # Initialize a variable to store the capture thread

def assign_threat_level(packet):
    """Determine the threat level of a packet based on its contents."""
    threat_level = "Low"  # Default to low threat level

    # Example criteria for threat levels
    if packet.haslayer('ICMP'):
        threat_level = "Medium"  # ICMP packets can be suspicious
    elif packet.haslayer('TCP'):
        # Rule: High threat for HTTP traffic on port 80
        if packet['TCP'].dport == 80:
            threat_level = "High"
        
        # Rule: High threat for large packet sizes
        if len(packet) > 1500:  # Example threshold
            threat_level = "High"
        
        # Rule: High threat for suspicious TCP flags
        if 'S' in packet['TCP'].flags and 'F' in packet['TCP'].flags:
            threat_level = "High"
        
        # Rule: Medium threat for connections to unusual ports
        if packet['TCP'].dport not in [80, 443]:  # Example list of normal ports
            threat_level = "Medium"

    return threat_level

def packet_callback(packet):
    """Callback function for processing captured packets."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    summary = packet.summary()
    threat_level = assign_threat_level(packet)

    # Create a dictionary to store packet information with more detail
    packet_data = {
        "timestamp": timestamp,
        "summary": summary,
        "threat_level": threat_level,
        "raw": packet.show(dump=True),  # Raw representation of the packet
        "fields": {}
    }
    
    # Extract detailed fields based on layers present in the packet
    if packet.haslayer(Ether):
        packet_data["fields"]["dst"] = packet[Ether].dst
        packet_data["fields"]["src"] = packet[Ether].src
        packet_data["fields"]["type"] = packet[Ether].type

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        packet_data["fields"]["ip_src"] = ip_layer.src
        packet_data["fields"]["ip_dst"] = ip_layer.dst
        packet_data["fields"]["ttl"] = ip_layer.ttl
        packet_data["fields"]["protocol"] = ip_layer.proto

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        packet_data["fields"]["tcp_sport"] = tcp_layer.sport
        packet_data["fields"]["tcp_dport"] = tcp_layer.dport
        packet_data["fields"]["tcp_flags"] = str(tcp_layer.flags)  # Convert to string

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        packet_data["fields"]["udp_sport"] = udp_layer.sport
        packet_data["fields"]["udp_dport"] = udp_layer.dport

    packets.append(packet_data)  # Store packet data in global list

def capture_packets():
    """Capture packets and run indefinitely."""
    while capturing:  # Continuously check the capturing state
        sniff(prn=packet_callback, store=False, timeout=1)  # Capture packets with a timeout

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['GET'])
def start_capture():
    global capturing, capture_thread
    if not capturing:  # Only start a new thread if not already capturing
        capturing = True
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()
        return jsonify({"status": "Packet capture started!"})
    else:
        return jsonify({"status": "Packet capture is already running!"})

@app.route('/stop', methods=['GET'])
def stop_capture():
    global capturing
    if capturing:
        capturing = False  # This will signal the capture thread to stop
        capture_thread.join()  # Wait for the thread to finish
        return jsonify({"status": "Packet capture stopped!"})
    else:
        return jsonify({"status": "No packet capture is running!"})

@app.route('/clear', methods=['GET'])
def clear_packets():
    global packets
    packets = []  # Clear the packets list
    return jsonify({"status": "Packet log cleared!"})

@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify(packets)

@app.route('/save/<int:packet_index>', methods=['GET'])
def save_packet(packet_index):
    if 0 <= packet_index < len(packets):
        with open(f'packet_{packet_index}.json', 'w') as f:
            json.dump(packets[packet_index], f, indent=4)
        return jsonify({"status": f"Packet {packet_index} saved!"})
    else:
        return jsonify({"status": "Invalid packet index!"})

if __name__ == '__main__':
    app.run(debug=True)
