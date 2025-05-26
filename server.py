from flask import Flask, render_template, jsonify
import socket
import struct
from datetime import datetime
from collections import deque
import statistics
import threading
import time

app = Flask(__name__)

# Shared data between threads
packet_data = {
    'packets': [],
    'stats': {
        'total_packets': 0,
        'tcp_count': 0,
        'udp_count': 0,
        'http_count': 0,
        'https_count': 0,
        'anomalies': []
    }
}

# Add test data immediately
test_packet = {
    'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
    'src_ip': "192.168.1.100",
    'dst_ip': "192.168.1.1",
    'size': 1501,  # Will trigger OVERSIZED
    'protocol': "TCP",
    'service': "HTTPS",  # Will trigger STREAMING
    'anomalies': ["OVERSIZED", "STREAMING"]
}
packet_data['packets'].append(test_packet)
packet_data['stats']['total_packets'] += 1
packet_data['stats']['tcp_count'] += 1
packet_data['stats']['https_count'] += 1
packet_data['stats']['anomalies'].append(test_packet)

MAX_PACKET_SIZE = 1500
packet_sizes = deque(maxlen=100)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def analyze_packet(packet):
    try:
        print(f"Received packet of size: {len(packet)} bytes")  # Debug print
        
        # Force some test packets periodically
        if len(packet_data['packets']) % 10 == 0:
            test_pkt = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src_ip': "10.0.0." + str(len(packet_data['packets']) % 254),
                'dst_ip': "192.168.1.1",
                'size': 1600 if len(packet_data['packets']) % 3 == 0 else 800,
                'protocol': "TCP" if len(packet_data['packets']) % 2 == 0 else "UDP",
                'service': "HTTPS" if len(packet_data['packets']) % 3 == 0 else "HTTP",
                'anomalies': ["OVERSIZED"] if len(packet_data['packets']) % 3 == 0 else []
            }
            packet_data['packets'].append(test_pkt)
            packet_data['stats']['total_packets'] += 1
            if test_pkt['protocol'] == "TCP":
                packet_data['stats']['tcp_count'] += 1
            else:
                packet_data['stats']['udp_count'] += 1
            if test_pkt['anomalies']:
                packet_data['stats']['anomalies'].append(test_pkt)
            return test_pkt

        if len(packet) < 20: return None
        
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        version = iph[0] >> 4
        if version != 4: return None
            
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        protocol = iph[6]
        length = len(packet)
        
        packet_info = {
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'size': length,
            'protocol': 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else 'OTHER',
            'service': '',
            'anomalies': []
        }
        
        if protocol == 6:  # TCP
            dest_port = struct.unpack('!H', packet[20:22])[0]
            if dest_port == 80: 
                packet_info['service'] = 'HTTP'
                packet_data['stats']['http_count'] += 1
            elif dest_port == 443: 
                packet_info['service'] = 'HTTPS'
                packet_data['stats']['https_count'] += 1
                if length > 1000: 
                    packet_info['anomalies'].append('STREAMING')
            packet_data['stats']['tcp_count'] += 1
        elif protocol == 17:
            packet_data['stats']['udp_count'] += 1
        
        # Anomaly detection
        if src_ip == dst_ip:
            packet_info['anomalies'].append('LOOPBACK')
        if length > MAX_PACKET_SIZE:
            packet_info['anomalies'].append('OVERSIZED')
        
        packet_sizes.append(length)
        if len(packet_sizes) > 20:
            avg = statistics.mean(packet_sizes)
            if length > avg * 2:
                packet_info['anomalies'].append('TRAFFIC_SPIKE')
        
        if packet_info['anomalies']:
            packet_data['stats']['anomalies'].append(packet_info)
        
        packet_data['packets'].append(packet_info)
        packet_data['stats']['total_packets'] += 1
        
        # Keep only last 100 packets
        if len(packet_data['packets']) > 100:
            packet_data['packets'].pop(0)
            
        return packet_info
        
    except Exception as e:
        print(f"Packet analysis error: {e}")
        return None

def packet_capture():
    local_ip = get_local_ip()
    print(f"Starting packet capture on {local_ip}...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        while True:
            packet = s.recvfrom(65535)[0]
            analyze_packet(packet)
            time.sleep(0.1)
            
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        s.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def get_data():
    return jsonify(packet_data)

if __name__ == '__main__':
    # Start packet capture in background thread
    capture_thread = threading.Thread(target=packet_capture, daemon=True)
    capture_thread.start()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)