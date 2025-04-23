from scapy.all import *
import time
from datetime import datetime
import socket

def get_host_ip():
    """Get the primary IP address of the host machine"""
    try:
        # Create a socket and connect to an external server
        # This doesn't actually establish a connection but gives us the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def packet_callback(packet):
    """Simple callback to print packet info"""
    print(f"[{datetime.now()}] {packet.summary()}")
    # Add more detailed info for debugging
    if packet.haslayer(IP):
        print(f"    IP: {packet[IP].src} -> {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
    if packet.haslayer(UDP):
        print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

def main():
    """Test packet capture functionality"""
    print("Starting packet capture test...")
    print(f"Scapy version: {conf.version}")
    print(f"Using pcap: {conf.use_pcap}")
    print(f"Using Npcap: {conf.use_npcap}")
    
    # Get the host's IP address
    host_ip = get_host_ip()
    print(f"Host IP address: {host_ip}")
    
    # List available interfaces
    print("\nAvailable interfaces:")
    for iface_name in conf.ifaces:
        iface = conf.ifaces[iface_name]
        if hasattr(iface, 'ip'):
            print(f"  - {iface_name}: {iface.ip}")
        else:
            print(f"  - {iface_name}")
    
    # Try to find a good interface to use
    interface = None
    try:
        # First try to use the interface with the host's IP
        if host_ip:
            for iface_name in conf.ifaces:
                iface = conf.ifaces[iface_name]
                if hasattr(iface, 'ip') and iface.ip == host_ip:
                    interface = iface_name
                    print(f"\nSelected interface: {interface} with IP {iface.ip}")
                    break
        
        # If no interface with host IP, fall back to any non-loopback interface with an IP
        if not interface:
            for iface_name in conf.ifaces:
                iface = conf.ifaces[iface_name]
                if hasattr(iface, 'ip') and iface.ip != '0.0.0.0' and not iface.ip.startswith('127.'):
                    interface = iface_name
                    print(f"\nSelected interface: {interface} with IP {iface.ip}")
                    break
    except Exception as e:
        print(f"Error selecting interface: {e}")
    
    print(f"\nStarting capture on interface: {interface}")
    print("Press Ctrl+C to stop")
    
    try:
        # Capture packets for 30 seconds
        sniff(prn=packet_callback, store=False, iface=interface, timeout=30)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error during capture: {e}")
    
    print("Capture test completed")

if __name__ == "__main__":
    main()