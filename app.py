# ///////////////////////////////////////////
# /////////    Main Dev Only  ///////////////
# ///////////////////////////////////////////


from datetime import datetime
import ipaddress
from streamlit_folium import st_folium
import numpy as np
import subprocess
from streamlit_theme import st_theme
import plost
from collections import Counter
import json
import requests
import streamlit as st
import os
import random
from streamlit_folium import folium_static
from folium.plugins import MarkerCluster
import folium
from scapy.all import rdpcap
from scapy.all import RawPcapReader, Ether
from scapy.utils6 import in6_addrtovendor
import collections
import tempfile
import sys
import pandas as pd
from scapy.utils import corrupt_bytes
from utils.security.security import SecurityPatternAnalyzer
from streamlit_echarts import st_echarts
import streamlit.components.v1 as components
import geoip2.database
import pydeck as pdk
import folium
from streamlit_option_menu import option_menu
from utils.pcap_decode import FastPcapDecode
import streamlit.components.v1 as components
from mac_vendor_lookup import MacLookup
from mac_vendor_lookup import VendorNotFoundError
import time
import plotly.express as px
from utils.get_geo import IPMapGenerator
from utils.analysis import PcapAnalyzer

mac = MacLookup()
PCAPS = None  # Packets
pcap_decode = FastPcapDecode()
map_gen = IPMapGenerator()


if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None

if 'pcap_data' not in st.session_state:
    st.session_state.pcap_data = None

def get_all_pcap(PCAPS, PD):
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Protocol':
            if value == pcap.get('Protocol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    return pcaps


def process_json_data(json_data):
    # Convert JSON data to a pandas DataFrame
    df = pd.DataFrame.from_dict(json_data, orient='index')
    return df


# To Calculate Live Time
def calculate_live_time(pcap_data):
    timestamps = [float(packet.time) for packet in pcap_data]  # Convert to float
    start_time = min(timestamps)
    end_time = max(timestamps)
    live_time_duration = end_time - start_time
    live_time_duration_str = str(pd.Timedelta(seconds=live_time_duration))
    return start_time, end_time, live_time_duration, live_time_duration_str


# protocol length statistics
def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0, '1500-more': 0}
    if PCAPS is None:
        return pcap_len_dict
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0 < pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        elif pcap_len > 1500:
            pcap_len_dict['1500-more'] += 1
        else:
            pass
    return pcap_len_dict


# protocol freq statistics
def common_proto_statistic(PCAPS):
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['HTTP'] = 0
    common_proto_dict['HTTPS'] = 0
    common_proto_dict['Others'] = 0

    if PCAPS is None:
        return common_proto_dict
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            common_proto_dict['IP'] += 1
        elif pcap.haslayer("IPv6"):
            common_proto_dict['IPv6'] += 1
        if pcap.haslayer("TCP"):
            common_proto_dict['TCP'] += 1
        elif pcap.haslayer("UDP"):
            common_proto_dict['UDP'] += 1
        if pcap.haslayer("ARP"):
            common_proto_dict['ARP'] += 1
        elif pcap.haslayer("ICMP"):
            common_proto_dict['ICMP'] += 1
        elif pcap.haslayer("DNS"):
            common_proto_dict['DNS'] += 1
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                common_proto_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                common_proto_dict['HTTPS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                common_proto_dict['DNS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("ICMPv6ND_NS"):
            common_proto_dict['ICMP'] += 1
        else:
            common_proto_dict['Others'] += 1
    return common_proto_dict


# maximum protocol statistics
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Protocol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict


# http/https Protocol Statistics
def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            ip = None
            if dport == 80 or dport == 443:
                ip = pcap.getlayer("IP").dst
            elif sport == 80 or sport == 443:
                ip = pcap.getlayer("IP").src
            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict


def https_stats_main(PCAPS):
    http_dict = http_statistic(PCAPS)
    http_dict = sorted(http_dict.items(),
                       key=lambda d: d[1], reverse=False)
    http_key_list = list()
    http_value_list = list()
    for key, value in http_dict:
        http_key_list.append(key)
        http_value_list.append(value)
    return http_key_list, http_value_list


# DNS Protocol Statistics
def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("DNSQR"):
            qname = pcap.getlayer("DNSQR").qname
            if qname in dns_dict:
                dns_dict[qname] += 1
            else:
                dns_dict[qname] = 1
    return dns_dict


def dns_stats_main(PCAPS):
    dns_dict = dns_statistic(PCAPS)
    dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
    dns_key_list = list()
    dns_value_list = list()
    for key, value in dns_dict:
        dns_key_list.append(key.decode('utf-8'))
        dns_value_list.append(value)
    return dns_key_list, dns_value_list


def time_flow(PCAPS):
    time_flow_dict = collections.OrderedDict()
    start = PCAPS[0].time
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(PCAPS[0].time)))] = len(
        corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS:
        timediff = pcap.time - start
        time_flow_dict[float('%.3f' % timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict


def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            if pcap.getlayer("IP").src == host_ip:
                data_flow_dict['OUT'] += 1
            elif pcap.getlayer("IP").dst == host_ip:
                data_flow_dict['IN'] += 1
            else:
                pass
    return data_flow_dict


def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            dst = pcap.getlayer("IP").dst
            src = pcap.getlayer("IP").src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(), key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(), key=lambda d: d[1], reverse=False)
    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)
    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)
    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)
    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)
    in_ip_dict = {'in_keyp': in_keyp_list, 'in_packet': in_packet_list, 'in_keyl': in_keyl_list, 'in_len': in_len_list,
                  'out_keyp': out_keyp_list, 'out_packet': out_packet_list, 'out_keyl': out_keyl_list,
                  'out_len': out_len_list}
    return in_ip_dict


def proto_flow(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer("IP"):
            proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer("IPv6"):
            proto_flow_dict['IPv6'] += pcap_len
        if pcap.haslayer("TCP"):
            proto_flow_dict['TCP'] += pcap_len
        elif pcap.haslayer("UDP"):
            proto_flow_dict['UDP'] += pcap_len
        if pcap.haslayer("ARP"):
            proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer("ICMP"):
            proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer("DNS"):
            proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("ICMPv6ND_NS"):
            proto_flow_dict['ICMP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict


def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Protocol']] += len(corrupt_bytes(pcap))
    return most_flow_dict


def page_file_upload():
    # # File upload
    # uploaded_file = st.file_uploader("Choose a CSV file", type=["csv","pcap", "cap"])
    #
    # # Store the uploaded file in session state
    # st.session_state.uploaded_file = uploaded_file
    #
    # if uploaded_file is not None:
    #     st.success("File uploaded successfully!")
    if "uploaded_file" not in st.session_state or st.session_state.uploaded_file is None:
        # File upload
        print('rentre')
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv", "pcap", "cap", 'pcapng'])

        if uploaded_file is not None:
            file_extension = os.path.splitext(uploaded_file.name)[1]

            # Save the uploaded file to a temporary location
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp_input:
                temp_input.write(uploaded_file.read())
                temp_input_path = temp_input.name

            if file_extension == ".pcapng" or is_pcapng(temp_input_path):
                st.warning("PCAPNG file detected. Converting to PCAP format...")
                print('pcapng detected')
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_output:
                    converted_path = convert_pcapng_to_pcap(temp_input_path, temp_output.name)
                if converted_path:
                    st.session_state.uploaded_file = converted_path
            else:
                st.session_state.uploaded_file = temp_input_path

        if st.session_state.uploaded_file is not None:
            print('voila')
            print(st.session_state["menu_option"])
            st.session_state["menu_option"] = 2
            st.rerun()
    else:
        # Display existing file info
        st.warning("An uploaded file already exists in the session state.")

        # Option to delete existing file and upload a new one
        delete_existing = st.button("Delete Existing File and Upload New File")
        if delete_existing:
            st.session_state.uploaded_file = None
            st.session_state["menu_option"] = 1
            page_file_upload()


def page_display_info():
    # Display uploaded file information
    if st.session_state.get("uploaded_file") is not None:
        # st.subheader("Uploaded File Information:")
        # st.write(f"File Name: {st.session_state.uploaded_file.name}")
        # st.write(f"File Type: {st.session_state.uploaded_file.type}")
        # st.write(f"File Size: {st.session_state.uploaded_file.size} bytes")
        file_details = {"File Name": st.session_state.uploaded_file.name,
                        "File Type": st.session_state.uploaded_file.type,
                        "File Size": st.session_state.uploaded_file.size}
        st.write(file_details)


def Intro():
    st.markdown("""
    ### 🛠️ How to Use the PCAP Reader Tool

    Welcome to the **PCAP Reader Web Application**! This tool is designed to help cybersecurity analysts and network engineers easily **analyze `.pcap` files** without diving into complex CLI tools.

    ---
    #### 🔍 Features Overview
    - 📤 **Upload**: Load your own `.pcap` file for analysis.
    - 📊 **Raw Data**: View parsed packet data in tabular form.
    - 📈 **Graph**: Visualize network activity and protocol flow.
    - 📐 **Analysis**: Explore vendor communications, top talkers, and more.
    - 🌍 **Geoplots**: See geographic locations of IPs if available.

    ---
    #### 🚀 Step-by-Step Usage

    1. **Go to the "Upload" tab**  
       Upload a `.pcap` file from your system. The file is processed automatically.

    2. **Review Parsed Packets in "Raw Data"**  
       Explore source/destination IPs, protocols, ports, timestamps, and more.

    3. **Switch to "Graph" or "Analysis" tabs**  
       Generate visualizations like packet timelines, communication heatmaps, protocol distributions, etc.

    4. **Use "Geoplots" (optional)**  
       If your PCAP contains public IP addresses, geolocation visualizations will be shown.

    ---
    #### 📁 Supported File Types
    - `.pcap`

    ⚠️ Files should not exceed the upload limit (typically 200MB depending on deployment settings).

    ---
    #### 🧩 Under the Hood
    This app uses:
    - `Scapy` for packet parsing
    - `Pandas` for data structuring
    - `Plotly` for interactive graphs
    - `Streamlit` for web-based interaction

    ---
    #### 🙋 Need Help?
    If you encounter any issues, contact the dev team or check the app logs in your console.

    ### Reminder
    This tool is a fork of the github project https://github.com/paresh2806/PCAP-Analyzer

    ### 👤Contact
    oscar.malandain@epitech.eu

    Enjoy analyzing! 🔎
    """)


def RawDataView():
    uploaded_file = st.session_state.uploaded_file
    if uploaded_file is not None:

        with st.spinner('Processing PCAP file, please wait...'):
            dataframe_data = pcap_decode.process_pcap(uploaded_file)
            st.session_state.pcap_data = dataframe_data

            all_columns = list(dataframe_data.columns)

        st.sidebar.header("Please Filter Here:")

        # Multiselect for filtering by protocol
        selected_protocols = st.sidebar.multiselect(
            "Select Protocol:",
            options=dataframe_data["Protocol"].unique().tolist(), default=None
        )

        # Sidebar slider for filtering by length
        filter_value_len = st.sidebar.slider(
            "Filter by Length (Bytes):",
            min_value=int(dataframe_data["len"].min()),
            max_value=int(dataframe_data["len"].max()) + 1,
            value=(int(dataframe_data["len"].min()), int(dataframe_data["len"].max()))
        )

        # Sidebar text input for filtering by Source
        filter_source = st.sidebar.text_input("Filter by Source:", "")

        # Sidebar text input for filtering by Destination
        filter_destination = st.sidebar.text_input("Filter by Destination:", "")

        # Apply filters
        Data_to_display_df = dataframe_data.copy()

        if selected_protocols:
            Data_to_display_df = Data_to_display_df[Data_to_display_df["Protocol"].isin(selected_protocols)]

        Data_to_display_df = Data_to_display_df[
            (Data_to_display_df["len"] >= filter_value_len[0]) &
            (Data_to_display_df["len"] <= filter_value_len[1])
        ]

        if filter_source:
            Data_to_display_df = Data_to_display_df[
                Data_to_display_df["Source"].str.contains(filter_source, case=False, na=False)
            ]

        if filter_destination:
            Data_to_display_df = Data_to_display_df[
                Data_to_display_df["Destination"].str.contains(filter_destination, case=False, na=False)
            ]

        st.write("Filtered PCAPs:")

        # Column selection
        column_check = st.checkbox("Do you want to filter the data by column-wise also?")
        if column_check:
            selected_columns = st.multiselect(
                "Select Columns to Display:",
                options=all_columns, default=all_columns
            )
            Data_to_display_df = Data_to_display_df[selected_columns]

        st.checkbox("Use container width", value=True, key="use_container_width")
        filtered_df = Data_to_display_df.drop(columns=['src_mac', 'dst_mac'], errors='ignore')
        st.dataframe(filtered_df, use_container_width=st.session_state.use_container_width)

        # Statistics Section
        st.subheader("Statistics of Selected Data")

        try:
            Data_to_display_df['time'] = pd.to_datetime(Data_to_display_df['time'])
            st.subheader("Time Range:")
            st.write("Earliest timestamp:", Data_to_display_df['time'].min())
            st.write("Latest timestamp:", Data_to_display_df['time'].max())
            st.write("Duration:", Data_to_display_df['time'].max() - Data_to_display_df['time'].min())
        except Exception:
            st.warning("Time format is invalid or missing.")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Packet Length Statistics:")
            st.table(Data_to_display_df['len'].describe())

            st.subheader("Source Counts:")
            st.table(Data_to_display_df['Source'].value_counts())

        with col2:
            st.subheader("Protocol Distribution:")
            st.table(Data_to_display_df['Protocol'].value_counts(normalize=True))

            st.subheader("Destination Counts:")
            st.table(Data_to_display_df['Destination'].value_counts())
    else:
        st.warning("Please upload a valid PCAP file.")





def DataPacketLengthStatistics(data):
    # st.write("Data Packet Length Statistics")
    data1 = {'pcap_len': list(data.keys()), 'count': list(data.values())}
    df1 = pd.DataFrame(data1)

    options = {
        "title": {"text": "Data Packet Length Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df1['pcap_len'], df1['count'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def CommonProtocolStatistics(data):
    st.write("Common Protocol Statistics")
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    # plost.bar_chart(data=df2, bar='protocol_type', value='number_of_packets')

    options = {
        "xAxis": {
            "type": "category",
            "data": df2.protocol_type.tolist(),
        },
        "yAxis": {"type": "value"},
        "series": [{"data": df2.number_of_packets.tolist(), "type": "bar"}],
    }
    st_echarts(options=options, height="500px")

def CommonProtocolStatistics_ploty(data):
    # st.write('Common Protocol Statistics')
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    fig = px.bar(df2, x='protocol_type', y='number_of_packets',color="protocol_type",title="Common Protocol Statistics")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)




def MostFrequentProtocolStatistics(data):
    # st.write("Data Packet Length Statistics")
    data3 = {'protocol_type': list(data.keys()), 'freq': list(data.values())}
    df3 = pd.DataFrame(data3)

    options = {
        "title": {"text": "Most Frequent Protocol Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df3['protocol_type'], df3['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }


    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def HTTP_HTTPSAccessStatistics(key,value):
    # st.write("HTTP/HTTPS Access Statistics")
    data4 = {'HTTP/HTTPS key': list(key),
             'HTTP/HTTPS value': list(value)}
    df4 = pd.DataFrame(data4)
    fig = px.bar(df4, x='HTTP/HTTPS key', y='HTTP/HTTPS value',color="HTTP/HTTPS key",title="HTTP/HTTPS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)



def DNSAccessStatistics(key, value):
    # st.write("DNS Access Statistics")
    data5 = {'dns_key': list(key),
             'dns_value': list(value)}
    df5 = pd.DataFrame(data5)
    fig = px.bar(df5, x='dns_key', y='dns_value', color="dns_key",title="DNS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def TimeFlowChart(data):
    data6 = {'Relative_Time': list(data.keys()), 'Packet_Bytes': list(data.values())}
    df6 = pd.DataFrame(data6)
    fig = px.line(df6, x='Relative_Time', y="Packet_Bytes",title="Time Flow Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def DataInOutStatistics(data):
    # st.write("Data In/Out Statistics")
    data7 = {'In/Out': list(data.keys()), 'freq': list(data.values())}
    df7 = pd.DataFrame(data7)

    options = {
        "title": {"text": "Data In/Out Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Data ",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df7['In/Out'], df7['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')

def convert_pcapng_to_pcap(input_file, output_file):
    try:
        subprocess.run(['editcap', '-F', 'pcap', input_file, output_file], check=True)
        return output_file
    except subprocess.CalledProcessError:
        st.error("Failed to convert PCAPNG to PCAP. Make sure editcap is installed.")
        return None

def is_pcapng(file_path):
    with open(file_path, 'rb') as f:
        magic_number = f.read(4)
        return magic_number == b'\x0a\x0d\x0d\x0a'

def TotalProtocolPacketFlow(data):
    # st.write("Total Protocol Packet Flow bar chart")
    data8 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df8 = pd.DataFrame(data8)

    options = {
        "title": {"text": "Total Protocol PacketFlow", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Protocols",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df8['Protocol'], df8['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')

def TotalProtocolPacketFlowbarchart(data):
    # st.write("Total Protocol Packet Flow bar chart")
    data9 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df9 = pd.DataFrame(data9)
    fig = px.bar(df9, x='Protocol', y='freq', color="Protocol",title="Total Protocol Packet Flow bar chart")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)


def InboundIPTrafficDataPacketCountChart(data):
    # st.write("Inbound IP Traffic Data Packet Count Chart")
    data10 = {'Inbound IP': list(data['in_keyp']), 'Number of Data Packets': list(data['in_packet'])}
    df10 = pd.DataFrame(data10)
    fig = px.bar(df10, x='Inbound IP', y='Number of Data Packets', color="Inbound IP",title="Inbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def InboundIPTotalTrafficChart(data):
    # st.write("Inbound IP Total Traffic Chart")
    data11 = {'Inbound IP': list(data['in_keyl']), 'Total Data Packet Traffic': list(data['in_len'])}
    df11 = pd.DataFrame(data11)
    fig = px.bar(df11, x='Inbound IP', y='Total Data Packet Traffic', color="Inbound IP",title="Inbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def OutboundIPTrafficDataPacketCountChart(data):  # ip_flow['out_keyp'], ip_flow['out_packet']
    # st.write("Outbound IP Traffic Data Packet Count Chart")
    data12 = {'Outbound IP': list(data['out_keyp']), 'Number of Data Packets': list(data['out_packet'])}
    df12 = pd.DataFrame(data12)
    fig = px.bar(df12, x='Outbound IP', y='Number of Data Packets', color="Outbound IP",title="Outbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def OutboundIPTotalTrafficChart(data):  # ip_flow['out_keyl'],ip_flow['out_len']
    st.write("Outbound IP Total Traffic Chart")
    data13 = {'Outbound IP': list(data['out_keyl']), 'Total Data Packet Traffic': list(data['out_len'])}
    df13 = pd.DataFrame(data13)
    fig = px.bar(df13, x='Outbound IP', y='Total Data Packet Traffic', color="Outbound IP",title="Outbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def extract_valid_ip(ip_string):
    if pd.isna(ip_string):
        return None
    ip_only = str(ip_string).split(":")[0]
    try:
        ipaddress.ip_address(ip_only)
        return ip_only
    except ValueError:
        return None

def main():
    st.set_page_config(page_title="PCAP Dashboard", page_icon="📈", layout="wide")
    theme = st_theme()

    if "menu_option" not in st.session_state:
        st.session_state["menu_option"] = 1

    # download from Bootstrap
    selected = option_menu(
        menu_title=None,
        options=["Home", "Upload", "Raw Data", "Graph", "Analysis", "Geoplots", "Security"],
        icons=["house", "upload", "files", "diagram-2", "graph-up", "globe", "shield-check"],
        menu_icon="cast",
        default_index=0,
        orientation="horizontal",
        manual_select=st.session_state['menu_option'],
        key="menu_4"
    )

    # Intro Page
    if selected == "Home":
        # Page header
        Intro()

    # File uploader
    if selected == "Upload":
        page_file_upload()
        # page_display_info()

    # Raw Data Visualizer and Filtering
    if selected == "Raw Data":
        st.subheader("Raw Data Can be Visualized Here")
        RawDataView()

    if selected == "Graph":
        uploaded_file = st.session_state.uploaded_file
        if uploaded_file is not None:
            df = st.session_state.pcap_data.copy()
            pcap_json = df.to_json(orient='records', date_format='iso')
            # Read the HTML template
            with open('graph.html', 'r') as f:
                html_template = f.read()
            
            html_data = html_template.replace(
                'const pcapData = {}', f'const pcapData = {pcap_json}'
            )

            html_file = html_data.replace(
                'const theme = {}', f'const theme = {theme}'
            )
            # Display the HTML with the data
            components.html(html_file, height=1000, width=None)
        else:
            st.subheader("Upload a file to see the graph")
    if selected == "Analysis":
        st.subheader("Dashboard")
        if "pcap_data" not in st.session_state:
            st.info("Please upload a PCAP file first to see the analysis.")
        else:
            # Check if we have data to analyze
            uploaded_file = st.session_state.uploaded_file
            if uploaded_file is not None:
                # Create tabs for different types of analysis
                analysis_tabs = st.tabs([
                    "📊 Analysis Dashboard", 
                    "🔍 Advanced Filters", 
                    "📑 Report Generation"
                ])
                
                with analysis_tabs[0]:
                    # Initialize the PcapAnalyzer with the data
                    data = st.session_state.pcap_data.copy()
                    analyzer = PcapAnalyzer(data, theme)
                    
                    # Display the full dashboard
                    analyzer.display_dashboard()
                
                with analysis_tabs[1]:
                    st.header("Advanced Analysis Filters")
                    
                    # Create additional analysis options
                    st.subheader("Custom Protocol Analysis")
                    
                    # Allow user to select specific protocols to compare
                    all_protocols = sorted(st.session_state.pcap_data['Protocol'].unique().tolist())
                    selected_protocols = st.multiselect(
                        "Select protocols to compare:", 
                        all_protocols,
                        default=all_protocols[:min(3, len(all_protocols))]
                    )
                    
                    if selected_protocols:
                        # Filter data for selected protocols
                        filtered_data = st.session_state.pcap_data[st.session_state.pcap_data['Protocol'].isin(selected_protocols)]
                        
                        # Create comparison charts
                        st.subheader("Protocol Comparison")
                        
                        # Protocol packet count
                        protocol_counts = filtered_data['Protocol'].value_counts()
                        fig = px.bar(
                            x=protocol_counts.index,
                            y=protocol_counts.values,
                            labels={'x': 'Protocol', 'y': 'Packet Count'},
                            color=protocol_counts.index,
                            title="Packet Count by Protocol"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Protocol data volume
                        protocol_volume = filtered_data.groupby('Protocol')['len'].sum()
                        fig = px.bar(
                            x=protocol_volume.index,
                            y=protocol_volume.values,
                            labels={'x': 'Protocol', 'y': 'Data Volume (bytes)'},
                            color=protocol_volume.index,
                            title="Data Volume by Protocol"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with analysis_tabs[2]:
                    st.header("PCAP Analysis Report Generation (Soon)")
                    
                    # Report customization options
                    st.subheader("Customize Report")
                    
                    report_title = st.text_input("Report Title", "PCAP Analysis Report")
                    
                    report_sections = st.multiselect(
                        "Select sections to include in the report",
                        ["Basic Statistics", "Time Analysis", "Protocol Analysis", 
                         "Network Analysis", "Vendor Analysis", "Packet Size Analysis"],
                        default=["Basic Statistics", "Protocol Analysis", "Network Analysis"]
                    )
                    
                    # Generate report button
                    if st.button("Generate PDF Report"):
                        st.info("PDF report generation would be implemented here.")
                        st.success("Report generated successfully!")
                        
                        # Download link (placeholder)
                        st.download_button(
                            label="Download Report",
                            data=b"Sample report content",
                            file_name="pcap_analysis_report.pdf",
                            mime="application/pdf"
                        )
            else:
                st.warning("Upload a file to see data analysis")
    if selected == "Geoplots":
        uploaded_file = st.session_state.uploaded_file
        if uploaded_file is not None:
            st.subheader("Geoplot")
            df = st.session_state.pcap_data
            source_ips = df['Source'].apply(extract_valid_ip)
            destination_ips = df['Destination'].apply(extract_valid_ip)
            all_ips = pd.concat([source_ips, destination_ips]).dropna().unique().tolist()
            ip_map = map_gen.generate_map(all_ips)
            st_folium(ip_map, use_container_width=True , height=900)
        else:
            st.warning("Upload a file to see data geolocation")
    if selected == "Security":
        st.subheader("Security")
        uploaded_file = st.session_state.uploaded_file
        if uploaded_file is None:
            st.info("Please upload a PCAP file first to perform security analysis.")
        else:
            security_analyzer = SecurityPatternAnalyzer(st.session_state.pcap_data)
            security_analyzer.display_security_dashboard()


if __name__ == "__main__":
    main()