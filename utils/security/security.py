import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
import numpy as np
from utils.security.port_scanning import add_port_scan_detection_tab

class SecurityPatternAnalyzer:
    def __init__(self, data):
        """Initialize with PCAP data."""
        self.data = data.copy()
        
        # Preprocess if not already done
        if 'src_ip' not in self.data.columns:
            self.data['src_ip'] = self.data['Source'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
            self.data['dst_ip'] = self.data['Destination'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
        
        # Extract ports for analysis
        self.data['src_port'] = self.data['Source'].apply(lambda x: x.split(':')[1] if ':' in str(x) else None)
        self.data['dst_port'] = self.data['Destination'].apply(lambda x: x.split(':')[1] if ':' in str(x) else None)
        
        # Convert time if needed
        if not pd.api.types.is_datetime64_any_dtype(self.data['time']):
            self.data['time'] = pd.to_datetime(self.data['time'])
    
    def display_security_dashboard(self):
        """Display a comprehensive security dashboard."""
        st.title("🔒 Network Security Pattern Analysis")

        tabs = st.tabs([
            "Port Scanning", 
            "Beaconing (C2)", 
            "Data Exfiltration", 
            "Protocol Anomalies", 
            "DNS Anomalies"
        ])
        
        # Port Scanning tab
        with tabs[0]:
            add_port_scan_detection_tab(self.data)
        
        # Beaconing tab
        with tabs[1]:
            st.subheader("Beaconing Detection (Command & Control)")
        
        # Data Exfiltration tab
        with tabs[2]:
            st.subheader("Data Exfiltration Detection")
        
        # Protocol Anomalies tab
        with tabs[3]:
            st.subheader("Protocol Anomalies")
        
        # DNS Anomalies tab
        with tabs[4]:
            st.subheader("DNS Anomalies")