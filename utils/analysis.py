import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from collections import Counter
import datetime
from io import BytesIO
import streamlit.components.v1 as components
import json

class PcapAnalyzer:
    def __init__(self, data, theme):
        """Initialize the PcapAnalyzer with pcap data.
        
        Args:
            data (pandas.DataFrame): Pcap data in the specified format
        """
        self.data = data
        self.theme = theme
        self.preprocess_data()
        
    def preprocess_data(self):
        """Preprocess the data for analysis."""
        # Convert time to datetime if it's not already
        if not pd.api.types.is_datetime64_any_dtype(self.data['time']):
            self.data['time'] = pd.to_datetime(self.data['time'])
            
        # Extract hour for time-based analysis
        self.data['hour'] = self.data['time'].dt.hour
        
        # Convert len to numeric if it's not already
        if not pd.api.types.is_numeric_dtype(self.data['len']):
            self.data['len'] = pd.to_numeric(self.data['len'], errors='coerce')
            
        # Extract IP addresses without ports
        self.data['src_ip'] = self.data['Source'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
        self.data['dst_ip'] = self.data['Destination'].apply(lambda x: x.split(':')[0] if ':' in str(x) else x)
        
    def display_dashboard(self):
        """Display the dashboard in Streamlit."""
        st.title("Network Capture Analysis Dashboard")
        
        # Basic statistics
        self.display_basic_stats()
        
        # Time series analysis
        self.display_time_analysis()
        
        # Protocol analysis
        self.display_protocol_analysis()
        
        # Network flow analysis
        self.display_network_analysis()
        
        # Vendor analysis
        self.display_vendor_analysis()
        
        # Packet size analysis
        self.display_packet_size_analysis()
        
    def display_basic_stats(self):
        """Display basic statistics about the pcap data."""
        st.header("📊 Basic Statistics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Packets", f"{len(self.data):,}")
            
        with col2:
            data_volume = self.data['len'].sum()
            if data_volume > 1024*1024:
                volume_str = f"{data_volume/(1024*1024):.2f} MB"
            else:
                volume_str = f"{data_volume/1024:.2f} KB"
            st.metric("Total Data Volume", volume_str)
            
        with col3:
            time_range = self.data['time'].max() - self.data['time'].min()
            hours = time_range.total_seconds() / 3600
            st.metric("Capture Duration", f"{hours:.2f} hours")
            
        # Show top protocols
        st.subheader("Top Protocols")
        protocol_counts = self.data['Protocol'].value_counts().head(5)
        
        fig = px.bar(
            x=protocol_counts.values,
            y=protocol_counts.index,
            orientation='h',
            labels={'x': 'Count', 'y': 'Protocol'},
            color=protocol_counts.values,
            color_continuous_scale='Viridis'
        )
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig, use_container_width=True)
        
    def display_time_analysis(self):
        """Display time-based analysis."""
        st.header("⏱️ Time Analysis")
        
        # Traffic over time
        st.subheader("Traffic Over Time")
        
        # Group by hour
        hourly_data = self.data.groupby(pd.Grouper(key='time', freq='s')).size().reset_index(name='count')
        
        fig = px.line(
            hourly_data, 
            x='time', 
            y='count',
            labels={'count': 'Packet Count', 'time': 'Time'},
            template='plotly_white'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # Traffic by hour of day
        st.subheader("Traffic by Hour of Day")
        hourly_pattern = self.data.groupby('hour').size().reset_index(name='count')
        
        fig = px.bar(
            hourly_pattern,
            x='hour',
            y='count',
            labels={'count': 'Packet Count', 'hour': 'Hour of Day'},
            color='count',
            color_continuous_scale='Viridis'
        )
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
        
    def display_protocol_analysis(self):
        """Display protocol-based analysis."""
        st.header("🔍 Protocol Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Protocol distribution
            protocol_distribution = self.data['Protocol'].value_counts()
            
            fig = px.pie(
                values=protocol_distribution.values,
                names=protocol_distribution.index,
                title="Protocol Distribution",
                template='plotly_white',
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            # Protocol data volume
            protocol_volume = self.data.groupby('Protocol')['len'].sum().sort_values(ascending=False)
            
            fig = px.bar(
                x=protocol_volume.index,
                y=protocol_volume.values,
                labels={'x': 'Protocol', 'y': 'Data Volume (bytes)'},
                color=protocol_volume.values,
                color_continuous_scale='Viridis',
                title="Data Volume by Protocol"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        # Protocol over time
        st.subheader("Protocol Usage Over Time")
        # Get top 5 protocols
        top_protocols = self.data['Protocol'].value_counts().head(5).index.tolist()
        
        # Filter data to include only top protocols
        filtered_data = self.data[self.data['Protocol'].isin(top_protocols)]
        
        # Group by time and protocol
        protocol_time = filtered_data.groupby([pd.Grouper(key='time', freq='S'), 'Protocol']).size().reset_index(name='count')
        
        fig = px.line(
            protocol_time,
            x='time',
            y='count',
            color='Protocol',
            labels={'count': 'Packet Count', 'time': 'Time'},
            template='plotly_white'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
    def display_network_analysis(self):
        """Display network flow analysis."""
        st.header("🌐 Network Flow Analysis")
        
        # Top sources
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Top Source IP Addresses")
            top_sources = self.data['src_ip'].value_counts().head(10)
            
            fig = px.bar(
                x=top_sources.values,
                y=top_sources.index,
                orientation='h',
                labels={'x': 'Packet Count', 'y': 'Source IP'},
                color=top_sources.values,
                color_continuous_scale='Viridis'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            st.subheader("Top Destination IP Addresses")
            top_destinations = self.data['dst_ip'].value_counts().head(10)
            
            fig = px.bar(
                x=top_destinations.values,
                y=top_destinations.index,
                orientation='h',
                labels={'x': 'Packet Count', 'y': 'Destination IP'},
                color=top_destinations.values,
                color_continuous_scale='Viridis'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        # Network graph
        st.subheader("Network Communication Graph")
        
        pcap_json = json.dumps(st.session_state.pcap_data.to_dict(orient='records'))
        # Read the HTML template
        with open('graph.html', 'r') as f:
            html_template = f.read()
        
        html_data = html_template.replace(
            'const pcapData = {}', f'const pcapData = {pcap_json}'
        )

        html_file = html_data.replace(
            'const theme = {}', f'const theme = {self.theme}'
        )
        # Display the HTML with the data
        components.html(html_file, height=1000, width=None)
        
    def display_vendor_analysis(self):
        """Display vendor-based analysis."""
        st.header("🏢 Vendor Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Source vendor distribution
            src_vendor_counts = self.data['src_vendor'].value_counts().head(10)
            
            fig = px.pie(
                values=src_vendor_counts.values,
                names=src_vendor_counts.index,
                title="Source Vendor Distribution",
                template='plotly_white'
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            # Destination vendor distribution
            dst_vendor_counts = self.data['dst_vendor'].value_counts().head(10)
            
            fig = px.pie(
                values=dst_vendor_counts.values,
                names=dst_vendor_counts.index,
                title="Destination Vendor Distribution",
                template='plotly_white'
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        
        # Vendor heatmap
        st.subheader("Vendor-to-Vendor Communication Heatmap")
        
        top_src_vendors = self.data['src_vendor'].value_counts().head(10).index.tolist()
        top_dst_vendors = self.data['dst_vendor'].value_counts().head(10).index.tolist()

        filtered_data = self.data[
            (self.data['src_vendor'].isin(top_src_vendors)) & 
            (self.data['dst_vendor'].isin(top_dst_vendors))
        ]

        vendor_matrix = pd.crosstab(filtered_data['src_vendor'], filtered_data['dst_vendor'])

        fig = go.Figure(data=go.Heatmap(
            z=vendor_matrix.values,
            x=vendor_matrix.columns.tolist(),
            y=vendor_matrix.index.tolist(),
            xgap=2,
            ygap=2,
            colorscale='Viridis',
            colorbar=dict(title="Packet Count")
        ))

        fig.update_layout(
            height=500,
            xaxis_title="Destination Vendor",
            yaxis_title="Source Vendor"
        )

        st.plotly_chart(fig, width=400)
        
    def display_packet_size_analysis(self):
        """Display packet size analysis."""
        st.header("📦 Packet Size Analysis")
                
        # Packet size distribution
        fig = px.histogram(
            self.data,
            x='len',
            nbins=50,
            labels={'len': 'Packet Size (bytes)', 'count': 'Frequency'},
            title="Packet Size Distribution",
            color_discrete_sequence=['#636EFA']
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # Packet size over time
        st.subheader("Packet Size Over Time")
        
        # Group by hour and calculate mean packet size
        hourly_size = self.data.groupby(pd.Grouper(key='time', freq='s'))['len'].mean().reset_index()
        
        fig = px.line(
            hourly_size,
            x='time',
            y='len',
            labels={'len': 'Average Packet Size (bytes)', 'time': 'Time'},
            title="Average Packet Size Over Time",
            template='plotly_white'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)