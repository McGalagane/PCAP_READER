import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import timedelta
import numpy as np

class PortScanDetector:
    def __init__(self):
        self.thresholds = {
            'horizontal': 15, 'vertical': 15, 'syn': 5, 'time_window': 60,
            'packet_rate': 10, 'fin': 5, 'xmas': 3, 'null': 3, 'ack': 10, 'udp': 10
        }
        self.results = None
        
    def preprocess_data(self, data):
        df = data.copy()
        if not pd.api.types.is_datetime64_any_dtype(df['time']):
            df['time'] = pd.to_datetime(df['time'])
        if 'src_ip' not in df.columns:
            df['src_ip'] = df['Source'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
            df['dst_ip'] = df['Destination'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
        if 'src_port' not in df.columns:
            df['src_port'] = df['Source'].apply(lambda x: x.split(':')[1] if ':' in str(x) and len(x.split(':')) > 1 else None)
            df['dst_port'] = df['Destination'].apply(lambda x: x.split(':')[1] if ':' in str(x) and len(x.split(':')) > 1 else None)
        return df.sort_values('time')
    
    def detect_port_scans(self, data):
        df = self.preprocess_data(data)
        scan_results = {
            'horizontal_scans': self._detect_horizontal_scans(df),
            'vertical_scans': self._detect_vertical_scans(df),
            'syn_scans': self._detect_syn_scans(df),
            'fin_scans': self._detect_fin_scans(df),
            'xmas_scans': self._detect_xmas_scans(df),
            'null_scans': self._detect_null_scans(df),
            'ack_scans': self._detect_ack_scans(df),
            'udp_scans': self._detect_udp_scans(df)
        }
        scan_counts = {scan_type: len(scans) for scan_type, scans in scan_results.items()}
        scan_results['scan_counts'] = scan_counts
        scan_results['total_potential_scanners'] = sum(scan_counts.values())
        self.results = scan_results
        return scan_results
    
    def _detect_horizontal_scans(self, df):
        port_activity = df.groupby(['src_ip', 'dst_ip'])['dst_port'].nunique().reset_index()
        port_activity.columns = ['src_ip', 'dst_ip', 'unique_ports']
        scanners = port_activity[port_activity['unique_ports'] >= self.thresholds['horizontal']]
        results = []
        for _, scan in scanners.iterrows():
            packets = df[(df['src_ip'] == scan['src_ip']) & (df['dst_ip'] == scan['dst_ip'])]
            unique_ports = packets['dst_port'].dropna().unique().tolist()
            unique_ports = [p for p in unique_ports if p is not None]
            if len(packets) >= 2:
                time_range = packets['time'].max() - packets['time'].min()
                time_span = time_range.total_seconds()
                pps = len(packets) / max(time_span, 1)
                high_speed = pps >= self.thresholds['packet_rate']
            else:
                time_span, pps, high_speed = 0, 0, False
            sequential = False
            if len(unique_ports) >= 3:
                try:
                    int_ports = [int(p) for p in unique_ports if p is not None]
                    diffs = [int_ports[i+1] - int_ports[i] for i in range(len(int_ports)-1)]
                    sequential = len(set(diffs[:5])) <= 2
                except (ValueError, TypeError, IndexError):
                    pass
            confidence = self._calculate_confidence(scan['unique_ports'], self.thresholds['horizontal'], high_speed, sequential)
            results.append({
                'src_ip': scan['src_ip'], 'dst_ip': scan['dst_ip'], 
                'unique_ports': int(scan['unique_ports']), 'port_list': unique_ports[:20],
                'time_span_seconds': time_span, 'packet_count': len(packets),
                'packets_per_second': pps, 'high_speed': high_speed,
                'sequential': sequential, 'confidence': confidence
            })
        return results
    
    def _detect_vertical_scans(self, df):
        port_activity = df.groupby(['src_ip', 'dst_port'])['dst_ip'].nunique().reset_index()
        port_activity.columns = ['src_ip', 'dst_port', 'unique_hosts']
        scanners = port_activity[port_activity['unique_hosts'] >= self.thresholds['vertical']]
        results = []
        for _, scan in scanners.iterrows():
            if pd.isna(scan['dst_port']):
                continue
            packets = df[(df['src_ip'] == scan['src_ip']) & (df['dst_port'] == scan['dst_port'])]
            unique_hosts = packets['dst_ip'].unique().tolist()
            if len(packets) >= 2:
                time_range = packets['time'].max() - packets['time'].min()
                time_span = time_range.total_seconds()
                pps = len(packets) / max(time_span, 1)
                high_speed = pps >= self.thresholds['packet_rate']
            else:
                time_span, pps, high_speed = 0, 0, False
            subnet_pattern = False
            if len(unique_hosts) >= 3:
                try:
                    ip_prefixes = ['.'.join(ip.split('.')[:3]) for ip in unique_hosts if ip is not None]
                    subnet_pattern = len(set(ip_prefixes)) <= 3
                except (AttributeError, IndexError):
                    pass
            confidence = self._calculate_confidence(scan['unique_hosts'], self.thresholds['vertical'], high_speed, subnet_pattern)
            results.append({
                'src_ip': scan['src_ip'], 'dst_port': scan['dst_port'],
                'unique_hosts': int(scan['unique_hosts']), 'host_list': unique_hosts[:20],
                'time_span_seconds': time_span, 'packet_count': len(packets),
                'packets_per_second': pps, 'high_speed': high_speed,
                'subnet_pattern': subnet_pattern, 'confidence': confidence
            })
        return results
    
    def _detect_syn_scans(self, df):
        tcp_data = df[df['Protocol'] == 'TCP'].copy()
        if len(tcp_data) == 0:
            return []
        tcp_data['is_syn'] = tcp_data['info'].str.contains('SYN', na=False) & ~tcp_data['info'].str.contains('ACK', na=False)
        tcp_data['is_syn_ack'] = tcp_data['info'].str.contains('SYN,ACK', na=False) | (tcp_data['info'].str.contains('SYN', na=False) & tcp_data['info'].str.contains('ACK', na=False))
        scanners = []
        for (src_ip, dst_ip), group in tcp_data.groupby(['src_ip', 'dst_ip']):
            syn_packets = group[group['is_syn']]
            if len(syn_packets) >= self.thresholds['syn']:
                syn_ack = tcp_data[(tcp_data['src_ip'] == dst_ip) & (tcp_data['dst_ip'] == src_ip) & tcp_data['is_syn_ack']]
                if len(syn_ack) < len(syn_packets) / 2:
                    unique_ports = syn_packets['dst_port'].dropna().unique().tolist()
                    unique_ports = [p for p in unique_ports if p is not None]
                    if len(syn_packets) >= 2:
                        time_range = syn_packets['time'].max() - syn_packets['time'].min()
                        time_span = time_range.total_seconds()
                        pps = len(syn_packets) / max(time_span, 1)
                        high_speed = pps >= self.thresholds['packet_rate']
                    else:
                        time_span, pps, high_speed = 0, 0, False
                    sequential = False
                    if len(unique_ports) >= 3:
                        try:
                            int_ports = [int(p) for p in unique_ports if p is not None]
                            int_ports.sort()
                            diffs = [int_ports[i+1] - int_ports[i] for i in range(len(int_ports)-1)]
                            sequential = len(set(diffs[:5])) <= 2
                        except (ValueError, TypeError, IndexError):
                            pass
                    confidence = self._calculate_confidence(len(syn_packets), self.thresholds['syn'], high_speed, sequential, len(syn_ack) == 0)
                    scanners.append({
                        'src_ip': src_ip, 'dst_ip': dst_ip, 'syn_packets': len(syn_packets),
                        'syn_ack_responses': len(syn_ack), 'unique_ports': len(unique_ports),
                        'port_list': unique_ports[:20], 'time_span_seconds': time_span,
                        'packets_per_second': pps, 'high_speed': high_speed,
                        'sequential': sequential, 'confidence': confidence
                    })
        return scanners
    
    def _detect_fin_scans(self, df):
        tcp_data = df[df['Protocol'] == 'TCP'].copy()
        if len(tcp_data) == 0:
            return []
        scanners = []
        for (src_ip, dst_ip), group in tcp_data.groupby(['src_ip', 'dst_ip']):
            fin_packets = group[group['info'].str.contains('FIN', na=False) & ~group['info'].str.contains('ACK', na=False)]
            if len(fin_packets) >= self.thresholds['fin']:
                unique_ports = fin_packets['dst_port'].dropna().unique().tolist()
                unique_ports = [p for p in unique_ports if p is not None]
                if len(fin_packets) >= 2:
                    time_range = fin_packets['time'].max() - fin_packets['time'].min()
                    time_span = time_range.total_seconds()
                    pps = len(fin_packets) / max(time_span, 1)
                    high_speed = pps >= self.thresholds['packet_rate']
                else:
                    time_span, pps, high_speed = 0, 0, False
                confidence = self._calculate_confidence(len(fin_packets), self.thresholds['fin'], high_speed, len(unique_ports) > self.thresholds['fin'])
                scanners.append({
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'fin_packets': len(fin_packets),
                    'unique_ports': len(unique_ports), 'port_list': unique_ports[:20],
                    'time_span_seconds': time_span, 'packets_per_second': pps,
                    'high_speed': high_speed, 'confidence': confidence
                })
        return scanners
    
    def _detect_xmas_scans(self, df):
        tcp_data = df[df['Protocol'] == 'TCP'].copy()
        if len(tcp_data) == 0:
            return []
        scanners = []
        for (src_ip, dst_ip), group in tcp_data.groupby(['src_ip', 'dst_ip']):
            xmas_packets = group[group['info'].str.contains('FIN', na=False) & group['info'].str.contains('PSH', na=False) & group['info'].str.contains('URG', na=False)]
            if len(xmas_packets) >= self.thresholds['xmas']:
                unique_ports = xmas_packets['dst_port'].dropna().unique().tolist()
                unique_ports = [p for p in unique_ports if p is not None]
                if len(xmas_packets) >= 2:
                    time_range = xmas_packets['time'].max() - xmas_packets['time'].min()
                    time_span = time_range.total_seconds()
                    pps = len(xmas_packets) / max(time_span, 1)
                    high_speed = pps >= self.thresholds['packet_rate']
                else:
                    time_span, pps, high_speed = 0, 0, False
                confidence = self._calculate_confidence(len(xmas_packets), self.thresholds['xmas'], high_speed, True, True)
                scanners.append({
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'xmas_packets': len(xmas_packets),
                    'unique_ports': len(unique_ports), 'port_list': unique_ports[:20],
                    'time_span_seconds': time_span, 'packets_per_second': pps,
                    'high_speed': high_speed, 'confidence': confidence
                })
        return scanners
    
    def _detect_null_scans(self, df):
        tcp_data = df[df['Protocol'] == 'TCP'].copy()
        if len(tcp_data) == 0:
            return []
        scanners = []
        for (src_ip, dst_ip), group in tcp_data.groupby(['src_ip', 'dst_ip']):
            null_packets = group[(group['info'].str.contains('Flags: None', na=False)) | (group['info'].str.contains('Flags:', na=False) & ~group['info'].str.contains('SYN', na=False) & ~group['info'].str.contains('ACK', na=False) & ~group['info'].str.contains('FIN', na=False) & ~group['info'].str.contains('RST', na=False) & ~group['info'].str.contains('PSH', na=False) & ~group['info'].str.contains('URG', na=False))]
            if len(null_packets) >= self.thresholds['null']:
                unique_ports = null_packets['dst_port'].dropna().unique().tolist()
                unique_ports = [p for p in unique_ports if p is not None]
                if len(null_packets) >= 2:
                    time_range = null_packets['time'].max() - null_packets['time'].min()
                    time_span = time_range.total_seconds()
                    pps = len(null_packets) / max(time_span, 1)
                    high_speed = pps >= self.thresholds['packet_rate']
                else:
                    time_span, pps, high_speed = 0, 0, False
                confidence = self._calculate_confidence(len(null_packets), self.thresholds['null'], high_speed, True, True)
                scanners.append({
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'null_packets': len(null_packets),
                    'unique_ports': len(unique_ports), 'port_list': unique_ports[:20],
                    'time_span_seconds': time_span, 'packets_per_second': pps,
                    'high_speed': high_speed, 'confidence': confidence
                })
        return scanners
    
    def _detect_ack_scans(self, df):
        tcp_data = df[df['Protocol'] == 'TCP'].copy()
        if len(tcp_data) == 0:
            return []
        scanners = []
        for (src_ip, dst_ip), group in tcp_data.groupby(['src_ip', 'dst_ip']):
            ack_packets = group[group['info'].str.contains('ACK', na=False) & ~group['info'].str.contains('SYN', na=False) & ~group['info'].str.contains('FIN', na=False) & ~group['info'].str.contains('RST', na=False) & (group['info'].str.contains('Win: 0', na=False) | group['info'].str.contains('Win: 1024', na=False) | group['info'].str.contains('Win: 2048', na=False) | group['info'].str.contains('Win: 4096', na=False))]
            if len(ack_packets) >= self.thresholds['ack']:
                unique_ports = ack_packets['dst_port'].dropna().unique().tolist()
                unique_ports = [p for p in unique_ports if p is not None]
                if len(ack_packets) >= 2:
                    time_range = ack_packets['time'].max() - ack_packets['time'].min()
                    time_span = time_range.total_seconds()
                    pps = len(ack_packets) / max(time_span, 1)
                    high_speed = pps >= self.thresholds['packet_rate']
                else:
                    time_span, pps, high_speed = 0, 0, False
                confidence = self._calculate_confidence(len(ack_packets), self.thresholds['ack'], high_speed, len(unique_ports) > self.thresholds['ack'] // 2)
                scanners.append({
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'ack_packets': len(ack_packets),
                    'unique_ports': len(unique_ports), 'port_list': unique_ports[:20],
                    'time_span_seconds': time_span, 'packets_per_second': pps,
                    'high_speed': high_speed, 'confidence': confidence
                })
        return scanners
    
    def _detect_udp_scans(self, df):
        udp_data = df[df['Protocol'] == 'UDP'].copy()
        if len(udp_data) == 0:
            return []
        port_activity = udp_data.groupby(['src_ip', 'dst_ip'])['dst_port'].nunique().reset_index()
        port_activity.columns = ['src_ip', 'dst_ip', 'unique_ports']
        scanners = port_activity[port_activity['unique_ports'] >= self.thresholds['udp']]
        results = []
        for _, scan in scanners.iterrows():
            packets = udp_data[(udp_data['src_ip'] == scan['src_ip']) & (udp_data['dst_ip'] == scan['dst_ip'])]
            unique_ports = packets['dst_port'].dropna().unique().tolist()
            unique_ports = [p for p in unique_ports if p is not None]
            if len(packets) >= 2:
                time_range = packets['time'].max() - packets['time'].min()
                time_span = time_range.total_seconds()
                pps = len(packets) / max(time_span, 1)
                high_speed = pps >= self.thresholds['packet_rate']
            else:
                time_span, pps, high_speed = 0, 0, False
            sequential = False
            if len(unique_ports) >= 3:
                try:
                    int_ports = [int(p) for p in unique_ports if p is not None]
                    int_ports.sort()
                    diffs = [int_ports[i+1] - int_ports[i] for i in range(len(int_ports)-1)]
                    sequential = len(set(diffs[:5])) <= 2
                except (ValueError, TypeError, IndexError):
                    pass
            confidence = self._calculate_confidence(scan['unique_ports'], self.thresholds['udp'], high_speed, sequential)
            results.append({
                'src_ip': scan['src_ip'], 'dst_ip': scan['dst_ip'],
                'unique_ports': int(scan['unique_ports']), 'port_list': unique_ports[:20],
                'time_span_seconds': time_span, 'packet_count': len(packets),
                'packets_per_second': pps, 'high_speed': high_speed,
                'sequential': sequential, 'confidence': confidence
            })
        return results
    
    def _calculate_confidence(self, count, threshold, high_speed=False, pattern_match=False, additional_factor=False):
        base = 0
        if count >= threshold * 3: base = 3
        elif count >= threshold * 2: base = 2
        elif count >= threshold * 1.5: base = 1
        total = base + (1 if high_speed else 0) + (1 if pattern_match else 0) + (1 if additional_factor else 0)
        if total >= 4: return "Very High"
        elif total == 3: return "High"
        elif total == 2: return "Medium"
        else: return "Low"
    
    def display_port_scan_results(self):
        if self.results is None:
            st.error("No scan detection results available. Run detect_port_scans() first.")
            return
        
        scan_results = self.results
        st.header("Port Scan Detection Results")
        
        # Summary
        total_scans = scan_results['total_potential_scanners']
        if total_scans > 0:
            st.warning(f"Detected {total_scans} potential port scanning activities")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Horizontal Scans", scan_results['scan_counts']['horizontal_scans'])
                st.metric("SYN Scans", scan_results['scan_counts']['syn_scans'])
                st.metric("FIN Scans", scan_results['scan_counts']['fin_scans'])
                st.metric("NULL Scans", scan_results['scan_counts']['null_scans'])
            with col2:
                st.metric("Vertical Scans", scan_results['scan_counts']['vertical_scans'])
                st.metric("XMAS Scans", scan_results['scan_counts']['xmas_scans'])
                st.metric("ACK Scans", scan_results['scan_counts']['ack_scans'])
                st.metric("UDP Scans", scan_results['scan_counts']['udp_scans'])
        else:
            st.success("No port scanning activity detected")
            return
        
        tabs = st.tabs(["Horizontal", "Vertical", "SYN", "FIN", "XMAS", "NULL", "ACK", "UDP"])
        
        # Horizontal Scans Tab
        with tabs[0]:
            st.subheader("Horizontal Port Scans")
            st.markdown("*Scanning multiple ports on a single host*")
            
            if len(scan_results['horizontal_scans']) > 0:
                h_scans_df = pd.DataFrame(scan_results['horizontal_scans'])
                st.dataframe(h_scans_df)
                
                if len(h_scans_df) > 1:
                    st.subheader("Top Scanners")
                    fig = px.bar(
                        h_scans_df.sort_values('unique_ports', ascending=False).head(10),
                        x='src_ip', y='unique_ports', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'unique_ports': 'Ports Scanned'},
                        title="Top Horizontal Port Scanners"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No horizontal port scans detected")
        
        # Vertical Scans Tab
        with tabs[1]:
            st.subheader("Vertical Port Scans")
            st.markdown("*Scanning the same port across multiple hosts*")
            
            if len(scan_results['vertical_scans']) > 0:
                v_scans_df = pd.DataFrame(scan_results['vertical_scans'])
                st.dataframe(v_scans_df)
                
                if len(v_scans_df) > 1:
                    st.subheader("Top Scanners")
                    fig = px.bar(
                        v_scans_df.sort_values('unique_hosts', ascending=False).head(10),
                        x='src_ip', y='unique_hosts', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'unique_hosts': 'Hosts Scanned'},
                        title="Top Vertical Port Scanners"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No vertical port scans detected")
        
        # SYN Scans Tab
        with tabs[2]:
            st.subheader("SYN Scans (Half-Open)")
            st.markdown("*SYN packets without completing TCP handshake*")
            
            if len(scan_results['syn_scans']) > 0:
                syn_scans_df = pd.DataFrame(scan_results['syn_scans'])
                st.dataframe(syn_scans_df)
                
                if len(syn_scans_df) > 0:
                    st.subheader("SYN Scan Analysis")
                    fig = px.scatter(
                        syn_scans_df,
                        x='syn_packets', y='unique_ports', size='time_span_seconds', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        hover_data=['src_ip', 'dst_ip', 'syn_ack_responses'],
                        labels={'syn_packets': 'SYN Packets', 'unique_ports': 'Unique Ports'},
                        title="SYN Scan Analysis"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No SYN scans detected")
        
        # FIN Scans Tab
        with tabs[3]:
            st.subheader("FIN Scans")
            st.markdown("*FIN packets to determine closed ports*")
            
            if len(scan_results['fin_scans']) > 0:
                fin_scans_df = pd.DataFrame(scan_results['fin_scans'])
                st.dataframe(fin_scans_df)
                
                if len(fin_scans_df) > 0:
                    fig = px.scatter(
                        fin_scans_df,
                        x='fin_packets', y='unique_ports', size='time_span_seconds', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        hover_data=['src_ip', 'dst_ip'],
                        labels={'fin_packets': 'FIN Packets', 'unique_ports': 'Unique Ports'},
                        title="FIN Scan Analysis"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No FIN scans detected")
        
        # XMAS Scans Tab
        with tabs[4]:
            st.subheader("XMAS Scans")
            st.markdown("*Packets with FIN, PSH, URG flags set*")
            
            if len(scan_results['xmas_scans']) > 0:
                xmas_scans_df = pd.DataFrame(scan_results['xmas_scans'])
                st.dataframe(xmas_scans_df)
                
                if len(xmas_scans_df) > 0:
                    fig = px.bar(
                        xmas_scans_df.sort_values('xmas_packets', ascending=False),
                        x='src_ip', y='xmas_packets', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'xmas_packets': 'XMAS Packets'},
                        title="XMAS Scan Detection"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No XMAS scans detected")
        
        # NULL Scans Tab
        with tabs[5]:
            st.subheader("NULL Scans")
            st.markdown("*Packets with no flags set*")
            
            if len(scan_results['null_scans']) > 0:
                null_scans_df = pd.DataFrame(scan_results['null_scans'])
                st.dataframe(null_scans_df)
                
                if len(null_scans_df) > 0:
                    fig = px.bar(
                        null_scans_df.sort_values('null_packets', ascending=False),
                        x='src_ip', y='null_packets', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'null_packets': 'NULL Packets'},
                        title="NULL Scan Detection"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No NULL scans detected")
        
        # ACK Scans Tab
        with tabs[6]:
            st.subheader("ACK Scans")
            st.markdown("*ACK packets to map firewall rules*")
            
            if len(scan_results['ack_scans']) > 0:
                ack_scans_df = pd.DataFrame(scan_results['ack_scans'])
                st.dataframe(ack_scans_df)
                
                if len(ack_scans_df) > 0:
                    fig = px.bar(
                        ack_scans_df.sort_values('ack_packets', ascending=False),
                        x='src_ip', y='ack_packets', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'ack_packets': 'ACK Packets'},
                        title="ACK Scan Detection"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No ACK scans detected")
        
        # UDP Scans Tab
        with tabs[7]:
            st.subheader("UDP Scans")
            st.markdown("*UDP packets to identify available services*")
            
            if len(scan_results['udp_scans']) > 0:
                udp_scans_df = pd.DataFrame(scan_results['udp_scans'])
                st.dataframe(udp_scans_df)
                
                if len(udp_scans_df) > 0:
                    fig = px.bar(
                        udp_scans_df.sort_values('unique_ports', ascending=False),
                        x='src_ip', y='unique_ports', color='confidence',
                        color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                        labels={'src_ip': 'Source IP', 'unique_ports': 'Unique Ports'},
                        title="UDP Scan Detection"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No UDP scans detected")
        
            # Most aggressive scanners
            st.subheader("Most Aggressive Scanners")
            all_scanners = []
            scan_types = ['horizontal_scans', 'vertical_scans', 'syn_scans', 'fin_scans', 
                        'xmas_scans', 'null_scans', 'ack_scans', 'udp_scans']
            
            for scan_type in scan_types:
                for scan in scan_results[scan_type]:
                    all_scanners.append({
                        'src_ip': scan['src_ip'],
                        'scan_type': scan_type,
                        'confidence': scan['confidence']
                    })
            
            if all_scanners:
                scanner_df = pd.DataFrame(all_scanners)
                scanner_counts = scanner_df.groupby('src_ip').agg({
                    'scan_type': 'nunique',
                    'confidence': lambda x: 'Very High' if 'Very High' in x.values else 
                                        ('High' if 'High' in x.values else 
                                            ('Medium' if 'Medium' in x.values else 'Low'))
                }).reset_index()
                
                scanner_counts.columns = ['Source IP', 'Scan Techniques Used', 'Highest Confidence']
                scanner_counts = scanner_counts.sort_values(
                    by=['Scan Techniques Used', 'Highest Confidence'], 
                    ascending=[False, False]
                )
                
                st.dataframe(scanner_counts)
                
                fig = px.bar(
                    scanner_counts.head(10),
                    x='Source IP', y='Scan Techniques Used', color='Highest Confidence',
                    color_discrete_map={'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Very High': 'red'},
                    title="Most Aggressive Scanners by Scan Technique Diversity"
                )
                st.plotly_chart(fig, use_container_width=True)
    
    def adjust_thresholds(self, **kwargs):
        for key, value in kwargs.items():
            if key in self.thresholds:
                self.thresholds[key] = value
        return self.thresholds
    
    def get_thresholds(self):
        return self.thresholds

def add_port_scan_detection_tab(data):
    st.header("🔍 Port Scan Detection")
    
    detector = PortScanDetector()
    
    with st.expander("Detection Thresholds", expanded=False):
        col1, col2 = st.columns(2)
        with col1:
            horizontal = st.number_input("Horizontal Scan Threshold", min_value=3, value=detector.thresholds['horizontal'])
            vertical = st.number_input("Vertical Scan Threshold", min_value=3, value=detector.thresholds['vertical'])
            syn = st.number_input("SYN Scan Threshold", min_value=2, value=detector.thresholds['syn'])
            fin = st.number_input("FIN Scan Threshold", min_value=2, value=detector.thresholds['fin'])
        with col2:
            xmas = st.number_input("XMAS Scan Threshold", min_value=1, value=detector.thresholds['xmas'])
            null = st.number_input("NULL Scan Threshold", min_value=1, value=detector.thresholds['null'])
            ack = st.number_input("ACK Scan Threshold", min_value=3, value=detector.thresholds['ack'])
            udp = st.number_input("UDP Scan Threshold", min_value=3, value=detector.thresholds['udp'])
    
        detector.adjust_thresholds(
            horizontal=horizontal, vertical=vertical, syn=syn, fin=fin,
            xmas=xmas, null=null, ack=ack, udp=udp
        )
    
    with st.spinner('Detecting port scans...'):
        progress_bar = st.progress(0)
        results = detector.detect_port_scans(data)
        progress_bar.progress(100)
    
    detector.display_port_scan_results()