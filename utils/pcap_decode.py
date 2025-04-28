import dpkt
import socket
import pandas as pd
import datetime
from mac_vendor_lookup import MacLookup

class FastPcapDecode:
    def __init__(self):
        self.mac_lookup = MacLookup()
        self.mac_cache = {}

        # Load protocol mappings
        self.ETHER_DICT = self._load_dict('utils/protocol/ETHER')
        self.IP_DICT = self._load_dict('utils/protocol/IP')
        self.PORT_DICT = self._load_dict('utils/protocol/PORT')
        self.TCP_DICT = self._load_dict('utils/protocol/TCP')
        self.UDP_DICT = self._load_dict('utils/protocol/UDP')

    def _load_dict(self, path):
        proto_dict = {}
        try:
            with open(path, 'r', encoding='UTF-8') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) == 2:
                        proto_dict[int(parts[0])] = parts[1]
        except Exception:
            pass
        return proto_dict

    def get_mac_vendor(self, mac):
        if not mac or mac == 'Unknown':
            return "Unknown"
        if mac in self.mac_cache:
            return self.mac_cache[mac]
        try:
            vendor = self.mac_lookup.lookup(mac)
            self.mac_cache[mac] = vendor
            return vendor
        except Exception:
            return "Unknown"

    def mac_addr(self, mac_bytes):
        return ':'.join('%02x' % b for b in mac_bytes)

    def ip_to_str(self, ip_bytes):
        try:
            return socket.inet_ntop(socket.AF_INET, ip_bytes)
        except Exception:
            try:
                return socket.inet_ntop(socket.AF_INET6, ip_bytes)
            except Exception:
                return 'Unknown'

    def process_pcap(self, file_path):
        rows = []

        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                row = {
                    'time': datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'src_mac': 'Unknown',
                    'dst_mac': 'Unknown',
                    'src_vendor': 'Unknown',
                    'dst_vendor': 'Unknown',
                    'Source': 'Unknown',
                    'Destination': 'Unknown',
                    'Protocol': 'Unknown',
                    'len': len(buf),
                    'info': 'Unknown'
                }

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    row['src_mac'] = self.mac_addr(eth.src)
                    row['dst_mac'] = self.mac_addr(eth.dst)
                    row['src_vendor'] = self.get_mac_vendor(row['src_mac'])
                    row['dst_vendor'] = self.get_mac_vendor(row['dst_mac'])

                    row['info'] = str(eth.__class__.__name__)

                    # IP v4
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = self.ip_to_str(ip.src)
                        dst_ip = self.ip_to_str(ip.dst)

                        row['Source'] = src_ip
                        row['Destination'] = dst_ip

                        # TCP
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            row['Source'] = f"{src_ip}:{tcp.sport}"
                            row['Destination'] = f"{dst_ip}:{tcp.dport}"
                            row['Protocol'] = self.PORT_DICT.get(tcp.dport) or \
                                              self.PORT_DICT.get(tcp.sport) or \
                                              self.TCP_DICT.get(tcp.dport) or \
                                              self.TCP_DICT.get(tcp.sport) or 'TCP'
                        # UDP
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            row['Source'] = f"{src_ip}:{udp.sport}"
                            row['Destination'] = f"{dst_ip}:{udp.dport}"
                            row['Protocol'] = self.PORT_DICT.get(udp.dport) or \
                                              self.PORT_DICT.get(udp.sport) or \
                                              self.UDP_DICT.get(udp.dport) or \
                                              self.UDP_DICT.get(udp.sport) or 'UDP'
                        else:
                            row['Protocol'] = self.IP_DICT.get(ip.p, f"IP:{ip.p}")

                    # IP v6
                    elif isinstance(eth.data, dpkt.ip6.IP6):
                        ip6 = eth.data
                        src_ip = self.ip_to_str(ip6.src)
                        dst_ip = self.ip_to_str(ip6.dst)

                        row['Source'] = src_ip
                        row['Destination'] = dst_ip

                        if isinstance(ip6.data, dpkt.tcp.TCP):
                            tcp = ip6.data
                            row['Source'] = f"{src_ip}:{tcp.sport}"
                            row['Destination'] = f"{dst_ip}:{tcp.dport}"
                            row['Protocol'] = self.PORT_DICT.get(tcp.dport) or \
                                              self.PORT_DICT.get(tcp.sport) or \
                                              self.TCP_DICT.get(tcp.dport) or \
                                              self.TCP_DICT.get(tcp.sport) or 'TCP'
                        elif isinstance(ip6.data, dpkt.udp.UDP):
                            udp = ip6.data
                            row['Source'] = f"{src_ip}:{udp.sport}"
                            row['Destination'] = f"{dst_ip}:{udp.dport}"
                            row['Protocol'] = self.PORT_DICT.get(udp.dport) or \
                                              self.PORT_DICT.get(udp.sport) or \
                                              self.UDP_DICT.get(udp.dport) or \
                                              self.UDP_DICT.get(udp.sport) or 'UDP'
                        else:
                            row['Protocol'] = self.IP_DICT.get(ip6.nxt, f"IPv6:{ip6.nxt}")

                    else:
                        row['Protocol'] = self.ETHER_DICT.get(eth.type, f"Ether:{hex(eth.type)}")

                except Exception as e:
                    row['Protocol'] = 'Corrupt'
                    row['info'] = str(e)

                rows.append(row)

        return pd.DataFrame(rows)
