from scapy.all import *
import pandas as pd
import time
from collections import defaultdict
from datetime import datetime
import threading
import queue

# ================== CONFIGURATION ==================
INTERFACE = "en0"          # ← Change this to your interface (e.g. en0)
PACKET_THRESHOLD = 80      # Packets from one IP in 5 seconds = possible flood
TIME_WINDOW = 5            # seconds
# ===================================================

packet_queue = queue.Queue()
stats = defaultdict(lambda: {'count': 0, 'last_time': time.time(), 'ports': set()})

def alert(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"🚨 [ALERT] {timestamp} | {message}")

def extract_features(packet):
    if IP not in packet:
        return None
    
    features = {
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'length': len(packet),
        'timestamp': time.time()
    }
    
    if TCP in packet:
        features['dport'] = packet[TCP].dport
    elif UDP in packet:
        features['dport'] = packet[UDP].dport
    
    return features

def packet_callback(packet):
    features = extract_features(packet)
    if features:
        packet_queue.put(features)

def detection_engine():
    while True:
        if not packet_queue.empty():
            pkt = packet_queue.get()
            src = pkt['src_ip']
            now = time.time()
            
            # Update stats
            stats[src]['count'] += 1
            stats[src]['last_time'] = now
            if 'dport' in pkt:
                stats[src]['ports'].add(pkt['dport'])
            
            # Rule-based Anomaly Detection
            time_diff = now - stats[src]['last_time']
            
            if stats[src]['count'] > PACKET_THRESHOLD and time_diff < TIME_WINDOW:
                alert(f"High traffic from {src} - Possible Flood/Scan")
            
            # Unusual port scanning
            if len(stats[src]['ports']) > 15:
                alert(f"Possible Port Scan from {src} ({len(stats[src]['ports'])} ports)")
            
            # Reset count after some time
            if time_diff > 10:
                stats[src]['count'] = 0
                stats[src]['ports'].clear()

        time.sleep(0.01)  # Small delay to prevent high CPU

# ================== START SNIFFING ==================
print(f"🛡️ Starting Real-Time Anomaly Detector on interface: {INTERFACE}")
print("Press Ctrl+C to stop...\n")

try:
    # Start detection engine in background
    detector_thread = threading.Thread(target=detection_engine, daemon=True)
    detector_thread.start()
    
    # Start live packet capture
    sniff(iface=INTERFACE, prn=packet_callback, store=False, filter="ip")

except KeyboardInterrupt:
    print("\n\n🛑 Detector stopped by user.")
except PermissionError:
    print("❌ Permission error. Run with: sudo python real_time_anomaly_detector.py")
except Exception as e:
    print(f"Error: {e}")
