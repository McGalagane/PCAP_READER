#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import time
import requests
from mac_vendor_lookup import MacLookup


class PcapDecode:
    def __init__(self):
        #ETHER:读取以太网层协议配置文件
        with open('utils/protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        #IP:读取IP层协议配置文件
        with open('utils/protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        #PORT:读取应用层协议端口配置文件
        with open('utils/protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        #TCP:读取TCP层协议配置文件
        with open('utils/protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        #UDP:读取UDP层协议配置文件
        with open('utils/protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    def get_mac_vendor(self, mac_address):
        if not mac_address or mac_address == 'Unknown':
            return "Unknown"
        return MacLookup().lookup(mac_address)

    #解析以太网层协议
    def ether_decode(self, p):
        data = dict()
        if p.haslayer(Ether):
            # Store MAC addresses if available
            data['src_mac'] = p[Ether].src
            data['dst_mac'] = p[Ether].dst
            
            # Add vendor information
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
            data = self.ip_decode(p)
            
            # Make sure vendor info is preserved from above
            if 'vendor' not in data:
                data['vendor'] = 'Unknown'
                
            return data
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
            data['Source'] = 'Unknow'
            data['Destination'] = 'Unknow'
            data['src_mac'] = 'Unknown'
            data['dst_mac'] = 'Unknown'
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
            data['Protocol'] = 'Unknow'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    #解析IP层协议
    def ip_decode(self, p):
        data = dict()
        # If we're starting from this method directly, make sure we capture MAC addresses if they exist
        if p.haslayer(Ether) and 'src_mac' not in data:
            data['src_mac'] = p[Ether].src
            data['dst_mac'] = p[Ether].dst
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
        elif 'src_mac' not in data:
            data['src_mac'] = 'Unknown'
            data['dst_mac'] = 'Unknown'
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
            
        if p.haslayer(IP):  #2048:Internet IP (IPv4)
            ip = p.getlayer(IP)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        elif p.haslayer(IPv6):  #34525:IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):  #6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer(UDP): #17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = hex(p.type)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

    #解析TCP层协议
    def tcp_decode(self, p, ip):
        data = dict()
        # Ensure MAC addresses are included if available
        if p.haslayer(Ether):
            data['src_mac'] = p[Ether].src
            data['dst_mac'] = p[Ether].dst
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
        else:
            data['src_mac'] = 'Unknown'
            data['dst_mac'] = 'Unknown'
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
            
        tcp = p.getlayer(TCP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
        data['Source'] = ip.src + ":" + str(tcp.sport)
        data['Destination'] = ip.dst + ":" + str(tcp.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Protocol'] = "TCP"
        return data

    #解析UDP层协议
    def udp_decode(self, p, ip):
        data = dict()
        # Ensure MAC addresses are included if available
        if p.haslayer(Ether):
            data['src_mac'] = p[Ether].src
            data['dst_mac'] = p[Ether].dst
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
        else:
            data['src_mac'] = 'Unknown'
            data['dst_mac'] = 'Unknown'
            data['src_vendor'] = 'Unknown'
            data['dst_vendor'] = 'Unknown'
            
        udp = p.getlayer(UDP)
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(p.time)))
        data['Source'] = ip.src + ":" + str(udp.sport)
        data['Destination'] = ip.dst + ":" + str(udp.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.sport]
        else:
            data['Protocol'] = "UDP"
        return data