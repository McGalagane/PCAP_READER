import dpkt
import socket
import pandas as pd
import datetime
from mac_vendor_lookup import MacLookup
import binascii
import struct
import logging
import os
import json
from typing import List, Dict, Tuple, Any, Optional

class FastPcapDecode:
    def __init__(self):
        """Initialize the PCAP decoder with necessary lookup tables."""
        self.mac_lookup = MacLookup()
        self.mac_cache = {}
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("FastPcapDecode")
        
        # Load protocol mappings
        self.ETHER_DICT = self._load_dict('utils/protocol/ETHER')
        self.IP_DICT = self._load_dict('utils/protocol/IP')
        self.PORT_DICT = self._load_dict('utils/protocol/PORT')
        self.TCP_DICT = self._load_dict('utils/protocol/TCP')
        self.UDP_DICT = self._load_dict('utils/protocol/UDP')
        
        # TCP flags for decoding
        self.TCP_FLAGS = {
            'FIN': 0x01,
            'SYN': 0x02,
            'RST': 0x04,
            'PSH': 0x08,
            'ACK': 0x10,
            'URG': 0x20,
            'ECE': 0x40,
            'CWR': 0x80
        }
        
        # Protocol handlers
        self.protocol_handlers = {
            dpkt.ethernet.ETH_TYPE_IP: self._handle_ip,
            dpkt.ethernet.ETH_TYPE_ARP: self._handle_arp,
            dpkt.ethernet.ETH_TYPE_IP6: self._handle_ipv6,
            dpkt.ethernet.ETH_TYPE_PPP: self._handle_ppp
        }

    def _load_dict(self, path: str) -> Dict:
        """Load protocol dictionary from file."""
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Protocol dictionary not found: {path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading protocol dictionary {path}: {e}")
            return {}

    def _mac_to_vendor(self, mac: str) -> str:
        """Get vendor from MAC address using cache for performance."""
        if not mac:
            return ""
            
        if mac in self.mac_cache:
            return self.mac_cache[mac]
            
        try:
            vendor = self.mac_lookup.lookup(mac)
            self.mac_cache[mac] = vendor
            return vendor
        except Exception:
            self.mac_cache[mac] = ""
            return ""

    def _format_mac_address(self, mac_bytes: bytes) -> str:
        """Convert MAC address bytes to string format."""
        return ':'.join('%02x' % b for b in mac_bytes)

    def _format_ip_address(self, ip_bytes: bytes) -> str:
        """Convert IP address bytes to string format."""
        try:
            return socket.inet_ntop(socket.AF_INET, ip_bytes)
        except Exception:
            return ""

    def _format_ipv6_address(self, ipv6_bytes: bytes) -> str:
        """Convert IPv6 address bytes to string format."""
        try:
            return socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
        except Exception:
            return ""

    def _decode_tcp_flags(self, flags: int) -> str:
        """Decode TCP flags to human-readable format."""
        active_flags = []
        for flag_name, flag_value in self.TCP_FLAGS.items():
            if flags & flag_value:
                active_flags.append(flag_name)
        return ','.join(active_flags) if active_flags else "None"

    def _get_protocol_name(self, protocol_type: int, protocol_dict: Dict) -> str:
        """Get protocol name from protocol number."""
        return protocol_dict.get(str(protocol_type), f"Unknown ({protocol_type})")

    def _handle_tcp(self, tcp, src_ip: str, dst_ip: str) -> Tuple[str, str, str, str]:
        """Handle TCP packet and extract relevant information."""
        src_port = tcp.sport
        dst_port = tcp.dport
        
        # Determine protocol based on ports
        protocol = "TCP"
        if str(src_port) in self.PORT_DICT:
            protocol = self.PORT_DICT[str(src_port)]
        elif str(dst_port) in self.PORT_DICT:
            protocol = self.PORT_DICT[str(dst_port)]
            
        # Format source and destination with ports
        source = f"{src_ip}:{src_port}"
        destination = f"{dst_ip}:{dst_port}"
        
        # Extract TCP flags
        tcp_flags = self._decode_tcp_flags(tcp.flags)
        
        # Get sequence and acknowledgment numbers
        seq_num = tcp.seq
        ack_num = tcp.ack
        
        # Create info string
        info = f"Flags: {tcp_flags}, Seq: {seq_num}, Ack: {ack_num}, Win: {tcp.win}"
        
        # If it's HTTP and we have data
        if (src_port == 80 or dst_port == 80) and len(tcp.data) > 0:
            try:
                http_data = tcp.data.decode('utf-8', errors='ignore')
                if http_data.startswith('GET') or http_data.startswith('POST') or http_data.startswith('HTTP'):
                    # Extract first line of HTTP request/response
                    first_line = http_data.split('\r\n')[0]
                    info = f"HTTP: {first_line} - {info}"
                    protocol = "HTTP"
            except Exception:
                pass
                
        return source, destination, protocol, info

    def _handle_udp(self, udp, src_ip: str, dst_ip: str) -> Tuple[str, str, str, str]:
        """Handle UDP packet and extract relevant information."""
        src_port = udp.sport
        dst_port = udp.dport
        
        # Determine protocol based on ports
        protocol = "UDP"
        if str(src_port) in self.PORT_DICT:
            protocol = self.PORT_DICT[str(src_port)]
        elif str(dst_port) in self.PORT_DICT:
            protocol = self.PORT_DICT[str(dst_port)]
            
        # Format source and destination with ports
        source = f"{src_ip}:{src_port}"
        destination = f"{dst_ip}:{dst_port}"
        
        # Create info string
        info = f"Src Port: {src_port}, Dst Port: {dst_port}, Len: {len(udp.data)}"
        
        # Special handling for DNS
        if src_port == 53 or dst_port == 53:
            protocol = "DNS"
            try:
                dns = dpkt.dns.DNS(udp.data)
                if dns.qr == 0:  # Query
                    if len(dns.qd) > 0:
                        query_name = dns.qd[0].name
                        info = f"DNS Query: {query_name}"
                else:  # Response
                    if len(dns.an) > 0:
                        answer = dns.an[0]
                        if answer.type == dpkt.dns.DNS_A:
                            ip = socket.inet_ntoa(answer.rdata)
                            info = f"DNS Response: {answer.name} -> {ip}"
            except Exception:
                pass
                
        return source, destination, protocol, info

    def _handle_icmp(self, icmp, src_ip: str, dst_ip: str) -> Tuple[str, str, str, str]:
        """Handle ICMP packet and extract relevant information."""
        # ICMP types and codes
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        
        # Format source and destination
        source = src_ip
        destination = dst_ip
        
        # Get ICMP type and code
        icmp_type = icmp.type
        icmp_code = icmp.code
        
        # Format info string
        type_str = icmp_types.get(icmp_type, f"Type: {icmp_type}")
        info = f"ICMP {type_str}, Code: {icmp_code}"
        
        return source, destination, "ICMP", info

    def _handle_ip(self, ip, timestamp, eth_src, eth_dst, src_vendor, dst_vendor, length) -> Dict:
        """Handle IP packet and extract packet information."""
        src_ip = self._format_ip_address(ip.src)
        dst_ip = self._format_ip_address(ip.dst)
        
        # Default values
        source = src_ip
        destination = dst_ip
        protocol = self._get_protocol_name(ip.p, self.IP_DICT)
        info = f"IP {src_ip} -> {dst_ip}"
        
        # Handle different protocols
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            try:
                tcp = ip.data
                source, destination, protocol, info = self._handle_tcp(tcp, src_ip, dst_ip)
            except Exception as e:
                self.logger.debug(f"Error processing TCP: {e}")
                
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            try:
                udp = ip.data
                source, destination, protocol, info = self._handle_udp(udp, src_ip, dst_ip)
            except Exception as e:
                self.logger.debug(f"Error processing UDP: {e}")
                
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            try:
                icmp = ip.data
                source, destination, protocol, info = self._handle_icmp(icmp, src_ip, dst_ip)
            except Exception as e:
                self.logger.debug(f"Error processing ICMP: {e}")
                
        # Create packet dictionary
        packet = {
            'time': timestamp,
            'src_mac': eth_src,
            'dst_mac': eth_dst,
            'src_vendor': src_vendor,
            'dst_vendor': dst_vendor,
            'Source': source,
            'Destination': destination,
            'Protocol': protocol,
            'len': length,
            'info': info
        }
        
        return packet

    def _handle_arp(self, arp, timestamp, eth_src, eth_dst, src_vendor, dst_vendor, length) -> Dict:
        """Handle ARP packet and extract packet information."""
        # Get operation (request=1, reply=2)
        op_type = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"Unknown ({arp.op})"
        
        # Extract hardware addresses
        sha = self._format_mac_address(arp.sha)
        tha = self._format_mac_address(arp.tha)
        
        # Extract protocol addresses
        spa = self._format_ip_address(arp.spa)
        tpa = self._format_ip_address(arp.tpa)
        
        # Create info string
        if arp.op == 1:  # ARP request
            info = f"Who has {tpa}? Tell {spa}"
        elif arp.op == 2:  # ARP reply
            info = f"{spa} is at {sha}"
        else:
            info = f"ARP {op_type}: {spa}/{sha} -> {tpa}/{tha}"
            
        # Create packet dictionary
        packet = {
            'time': timestamp,
            'src_mac': eth_src,
            'dst_mac': eth_dst,
            'src_vendor': src_vendor,
            'dst_vendor': dst_vendor,
            'Source': spa,
            'Destination': tpa,
            'Protocol': f"ARP ({op_type})",
            'len': length,
            'info': info
        }
        
        return packet

    def _handle_ipv6(self, ipv6, timestamp, eth_src, eth_dst, src_vendor, dst_vendor, length) -> Dict:
        """Handle IPv6 packet and extract packet information."""
        src_ip = self._format_ipv6_address(ipv6.src)
        dst_ip = self._format_ipv6_address(ipv6.dst)
        
        # Default values
        source = src_ip
        destination = dst_ip
        protocol = f"IPv6 {ipv6.nxt}"
        info = f"IPv6 {src_ip} -> {dst_ip}"
        
        # TODO: Add specific handlers for ICMPv6, TCP over IPv6, etc.
        
        # Create packet dictionary
        packet = {
            'time': timestamp,
            'src_mac': eth_src,
            'dst_mac': eth_dst,
            'src_vendor': src_vendor,
            'dst_vendor': dst_vendor,
            'Source': source,
            'Destination': destination,
            'Protocol': protocol,
            'len': length,
            'info': info
        }
        
        return packet

    def _handle_ppp(self, ppp, timestamp, eth_src, eth_dst, src_vendor, dst_vendor, length) -> Dict:
        """Handle PPP packet (placeholder)."""
        # Create packet dictionary
        packet = {
            'time': timestamp,
            'src_mac': eth_src,
            'dst_mac': eth_dst,
            'src_vendor': src_vendor,
            'dst_vendor': dst_vendor,
            'Source': "PPP",
            'Destination': "PPP",
            'Protocol': "PPP",
            'len': length,
            'info': "Point-to-Point Protocol"
        }
        
        return packet

    def _extract_packet_info(self, ts, buf) -> Optional[Dict]:
        """Extract information from a single packet."""
        try:
            # Convert timestamp to datetime
            timestamp = datetime.datetime.fromtimestamp(ts)
            
            # Parse Ethernet frame
            eth = dpkt.ethernet.Ethernet(buf)
            
            # Get Ethernet addresses
            eth_src = self._format_mac_address(eth.src)
            eth_dst = self._format_mac_address(eth.dst)
            
            # Get MAC vendors
            src_vendor = self._mac_to_vendor(eth_src)
            dst_vendor = self._mac_to_vendor(eth_dst)
            
            # Get packet length
            length = len(buf)
            
            # Handle packet based on Ethernet type
            eth_type = eth.type
            
            if eth_type in self.protocol_handlers:
                return self.protocol_handlers[eth_type](eth.data, timestamp, eth_src, eth_dst, src_vendor, dst_vendor, length)
            else:
                # Unknown Ethernet type
                return {
                    'time': timestamp,
                    'src_mac': eth_src,
                    'dst_mac': eth_dst,
                    'src_vendor': src_vendor,
                    'dst_vendor': dst_vendor,
                    'Source': eth_src,
                    'Destination': eth_dst,
                    'Protocol': self._get_protocol_name(eth_type, self.ETHER_DICT),
                    'len': length,
                    'info': f"Unknown Ethernet Type: 0x{eth_type:04x}"
                }
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            return None

    def process_pcap(self, file_path: str) -> pd.DataFrame:
        """Process a PCAP file and return packet data as a DataFrame."""
        rows = []
        
        try:
            # Track processing progress
            self.logger.info(f"Processing PCAP file: {file_path}")
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                pcap_reader = dpkt.pcap.Reader(f)
                
                # Process each packet
                packet_count = 0
                for ts, buf in pcap_reader:
                    packet_info = self._extract_packet_info(ts, buf)
                    
                    if packet_info:
                        rows.append(packet_info)
                        
                    packet_count += 1
                    if packet_count % 10000 == 0:
                        self.logger.info(f"Processed {packet_count} packets...")
                        
            self.logger.info(f"Completed processing {len(rows)} valid packets from {file_path}")
            
            # Create DataFrame
            df = pd.DataFrame(rows)
            
            # Convert time column to datetime if it's not already
            if 'time' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['time']):
                df['time'] = pd.to_datetime(df['time'])
                
            return df
                
        except Exception as e:
            self.logger.error(f"Error processing PCAP file {file_path}: {e}")
            # Return empty DataFrame with expected columns if processing fails
            return pd.DataFrame(columns=[
                'time', 'src_mac', 'dst_mac', 'src_vendor', 'dst_vendor',
                'Source', 'Destination', 'Protocol', 'len', 'info'
            ])
            
    def process_pcap_quick(self, file_path: str, max_packets: int = None) -> pd.DataFrame:
        """Process a portion of PCAP file for quick preview."""
        rows = []
        
        try:
            with open(file_path, 'rb') as f:
                pcap_reader = dpkt.pcap.Reader(f)
                
                # Process limited number of packets
                for i, (ts, buf) in enumerate(pcap_reader):
                    if max_packets is not None and i >= max_packets:
                        break
                        
                    packet_info = self._extract_packet_info(ts, buf)
                    
                    if packet_info:
                        rows.append(packet_info)
                        
            # Create DataFrame
            df = pd.DataFrame(rows)
            
            # Convert time column to datetime if it's not already
            if 'time' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['time']):
                df['time'] = pd.to_datetime(df['time'])
                
            return df
                
        except Exception as e:
            self.logger.error(f"Error quick-processing PCAP file {file_path}: {e}")
            # Return empty DataFrame with expected columns if processing fails
            return pd.DataFrame(columns=[
                'time', 'src_mac', 'dst_mac', 'src_vendor', 'dst_vendor',
                'Source', 'Destination', 'Protocol', 'len', 'info'
            ])
