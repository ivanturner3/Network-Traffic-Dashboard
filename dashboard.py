import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import *
import time
from datetime import datetime
import threading
import logging
import socket
import sys

# Configure logging
logging.basicConfig(
    level=logging.ERROR,  # Changed from DEBUG to ERROR
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""
    
    def __init__(self):
        self.protocol_map = {
            1: "ICMP", 
            6: "TCP", 
            17: "UDP"
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        logger.debug("PacketProcessor initialized")
        
    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')
    
    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:            
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }
                    
                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })
                        
                    # Add UDP-specific information
                    if UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })  
                    
                    self.packet_data.append(packet_info)
                    self.packet_count += 1
                    
                    # Keep only last 10,000 packets to prevent memory issue
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)    

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
            
    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to a pandas DataFrame"""
        with self.lock:
            if not self.packet_data:
                return pd.DataFrame()
            return pd.DataFrame(self.packet_data)
            
def create_visualization(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values = protocol_counts.values, 
            names = protocol_counts.index, 
            title = 'Protocol Distribution'
        )
        st.plotly_chart(fig_protocol, use_container_width=True)
        
        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
        fig_timeline = px.line(
            x = df_grouped.index, 
            y = df_grouped.values, 
            title = 'Packets per Second'
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x = top_sources.index, 
            y = top_sources.values, 
            title = 'Top Source IP Addresses'
        )
        st.plotly_chart(fig_sources, use_container_width=True)
        
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
    except Exception as e:
        logger.error(f"Error getting host IP: {e}")
        return None

def start_packet_capture():
    """Start packet capture in a separate thread"""
    processor = PacketProcessor()
    
    # Get the host's IP address
    host_ip = get_host_ip()
    logger.debug(f"Host IP address: {host_ip}")
    
    # Try to find a good interface to use
    interface = None
    try:
        # First try to use the interface with the host's IP
        if host_ip:
            for iface_name in conf.ifaces:
                iface = conf.ifaces[iface_name]
                if hasattr(iface, 'ip') and iface.ip == host_ip:
                    interface = iface_name
                    break
        
        # If no interface with host IP, fall back to any non-loopback interface with an IP
        if not interface:
            for iface_name in conf.ifaces:
                iface = conf.ifaces[iface_name]
                if hasattr(iface, 'ip') and iface.ip != '0.0.0.0' and not iface.ip.startswith('127.'):
                    interface = iface_name
                    break
    except Exception as e:
        logger.error(f"Error selecting interface: {e}")
    
    logger.debug(f"Using interface: {interface}")
    
    def capture_packets():
        try:
            sniff(prn=processor.process_packet, store=False, iface=interface, timeout=None)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}", exc_info=True)
    
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    return processor

def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")
    
    # Add a debug section that can be expanded
    with st.expander("Debug Information"):
        st.write("Scapy Configuration:")
        st.code(f"""
        Scapy version: {conf.version}
        Using pcap: {conf.use_pcap}
        Using Npcap: {conf.use_npcap}
        """)
        
        st.write("Available Interfaces:")
        interface_info = []
        for iface_name in conf.ifaces:
            iface = conf.ifaces[iface_name]
            if hasattr(iface, 'ip'):
                interface_info.append(f"{iface_name}: {iface.ip}")
            else:
                interface_info.append(f"{iface_name}")
        st.code("\n".join(interface_info))
    
    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()
        st.session_state.placeholder = st.empty()
        st.session_state.placeholder.info("Starting packet capture... Please wait.")
    
    # Get current data
    df = st.session_state.processor.get_dataframe()
    
    # Display packet count
    st.sidebar.metric("Packets Captured", len(df))
    st.sidebar.write(f"Session started: {datetime.fromtimestamp(st.session_state.start_time)}")
    
    # Add a manual refresh button
    if st.sidebar.button('Force Refresh'):
        logger.debug("Manual refresh triggered")
        st.rerun()
    
    # Only proceed with visualization if we have data
    if len(df) > 0:
        st.session_state.placeholder.empty()  # Clear the "waiting" message
        
        # Create dashboard layout
        col1, col2 = st.columns(2)
        
        # Display metrics
        with col1:
            st.metric("Total Packets", len(df))
        with col2:
            duration = time.time() - st.session_state.start_time
            st.metric("Capture Duration", f"{duration:.2f}s")
        
        # Display visualizations
        create_visualization(df)
    
        # Display recent packets
        st.subheader("Recent Packets")
        if len(df) > 0:
            st.dataframe(
                df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
                use_container_width=True
            )
    else:
        # If no packets yet, show a waiting message
        st.warning("Waiting for network traffic... This may take a few seconds.")
        
        # Show a more detailed message if we've been waiting too long
        elapsed = time.time() - st.session_state.start_time
        if elapsed > 10:
            st.error(f"""
            No packets captured after {elapsed:.1f} seconds. Possible issues:
            1. No active network traffic on the selected interface
            2. Permission issues with packet capture
            3. Firewall blocking packet capture
            
            Try running Streamlit as administrator or selecting a different interface.
            """)
    
    # Auto refresh less frequently to reduce CPU usage
    time.sleep(3)
    st.rerun()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Error in main function: {e}", exc_info=True)
        st.error(f"An error occurred: {e}")
