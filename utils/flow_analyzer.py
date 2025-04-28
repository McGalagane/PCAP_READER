#coding:UTF-8
import pyshark
import collections
import time

# Fonction pour obtenir la taille d'un paquet PyShark
def get_packet_length(packet):
    return int(packet.length) if hasattr(packet, 'length') else 0

# Temps écoulé
def time_flow(capture):
    """
    Crée un dictionnaire qui montre le flux de temps par rapport à la taille des paquets
    """
    time_flow_dict = collections.OrderedDict()
    
    # Reset la capture
    capture.reset()
    
    # Obtenir tous les paquets avec leur horodatage
    packets = []
    for packet in capture:
        if hasattr(packet, 'sniff_timestamp'):
            packets.append((float(packet.sniff_timestamp), get_packet_length(packet)))
    
    if not packets:
        return time_flow_dict
    
    # Trier par horodatage
    packets.sort(key=lambda x: x[0])
    
    # Le premier paquet a un temps relatif de 0
    start_time = packets[0][0]
    formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(start_time)))
    time_flow_dict[formatted_time] = packets[0][1]
    
    # Pour les autres paquets, calcul du temps relatif
    for timestamp, length in packets[1:]:
        time_diff = timestamp - start_time
        time_flow_dict[float('%.3f' % time_diff)] = length
    
    # Reset la capture
    capture.reset()
    
    return time_flow_dict

# Obtenir l'IP de l'hôte (l'adresse IP la plus commune)
def get_host_ip(capture):
    """
    Détermine l'adresse IP de l'hôte principal en fonction de la fréquence d'apparition
    """
    ip_list = []
    
    # Reset la capture
    capture.reset()
    
    for packet in capture:
        if hasattr(packet, 'ip'):
            ip_list.append(packet.ip.src)
            ip_list.append(packet.ip.dst)
    
    # Reset la capture
    capture.reset()
    
    if not ip_list:
        return "Unknown"
    
    # Trouver l'IP la plus fréquente
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip

# Statistiques de flux de données (entrées/sorties)
def data_flow(capture, host_ip):
    """
    Compte les paquets entrants et sortants de l'hôte
    """
    data_flow_dict = {'IN': 0, 'OUT': 0}
    
    # Reset la capture
    capture.reset()
    
    for packet in capture:
        if hasattr(packet, 'ip'):
            if packet.ip.src == host_ip:
                data_flow_dict['OUT'] += 1
            elif packet.ip.dst == host_ip:
                data_flow_dict['IN'] += 1
    
    # Reset la capture
    capture.reset()
    
    return data_flow_dict

# Statistiques détaillées sur les IPs entrant/sortant
def data_in_out_ip(capture, host_ip):
    """
    Analyse détaillée du trafic entrant et sortant par adresse IP
    """
    in_ip_packet_dict = dict()  # Nombre de paquets entrants par IP
    in_ip_len_dict = dict()     # Taille totale des paquets entrants par IP
    out_ip_packet_dict = dict() # Nombre de paquets sortants par IP
    out_ip_len_dict = dict()    # Taille totale des paquets sortants par IP
    
    # Reset la capture
    capture.reset()
    
    for packet in capture:
        if hasattr(packet, 'ip'):
            dst = packet.ip.dst
            src = packet.ip.src
            pcap_len = get_packet_length(packet)
            
            # Paquets entrants (vers l'hôte)
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            
            # Paquets sortants (depuis l'hôte)
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
    
    # Trier les dictionnaires
    in_packet_dict = sorted(in_ip_packet_dict.items(), key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_ip_len_dict.items(), key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_ip_packet_dict.items(), key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_ip_len_dict.items(), key=lambda d: d[1], reverse=False)
    
    # Extraire les clés et valeurs
    in_keyp_list = [key for key, _ in in_packet_dict]
    in_packet_list = [value for _, value in in_packet_dict]
    in_keyl_list = [key for key, _ in in_len_dict]
    in_len_list = [value for _, value in in_len_dict]
    out_keyp_list = [key for key, _ in out_packet_dict]
    out_packet_list = [value for _, value in out_packet_dict]
    out_keyl_list = [key for key, _ in out_len_dict]
    out_len_list = [value for _, value in out_len_dict]
    
    # Créer le dictionnaire final
    in_ip_dict = {
        'in_keyp': in_keyp_list, 
        'in_packet': in_packet_list, 
        'in_keyl': in_keyl_list, 
        'in_len': in_len_list,
        'out_keyp': out_keyp_list, 
        'out_packet': out_packet_list, 
        'out_keyl': out_keyl_list,
        'out_len': out_len_list
    }
    
    # Reset la capture
    capture.reset()
    
    return in_ip_dict

# Statistiques de flux de protocoles
def proto_flow(capture):
    """
    Analyse le flux de données par protocole
    """
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
    
    # Reset la capture
    capture.reset()
    
    for packet in capture:
        pcap_len = get_packet_length(packet)
        
        # Vérifier les couches réseau
        if hasattr(packet, 'ip'):
            proto_flow_dict['IP'] += pcap_len
        elif hasattr(packet, 'ipv6'):
            proto_flow_dict['IPv6'] += pcap_len
        
        # Vérifier les couches transport
        if hasattr(packet, 'tcp'):
            proto_flow_dict['TCP'] += pcap_len
            
            # Vérifier pour HTTP/HTTPS
            try:
                tcp_dport = int(packet.tcp.dstport)
                tcp_sport = int(packet.tcp.srcport)
                
                if tcp_dport == 80 or tcp_sport == 80:
                    proto_flow_dict['HTTP'] += pcap_len
                elif tcp_dport == 443 or tcp_sport == 443:
                    proto_flow_dict['HTTPS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            except:
                proto_flow_dict['Others'] += pcap_len
        
        elif hasattr(packet, 'udp'):
            proto_flow_dict['UDP'] += pcap_len
            
            # Vérifier pour DNS
            try:
                udp_dport = int(packet.udp.dstport)
                udp_sport = int(packet.udp.srcport)
                
                if udp_dport == 53 or udp_sport == 53 or udp_dport == 5353 or udp_sport == 5353:
                    proto_flow_dict['DNS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            except:
                proto_flow_dict['Others'] += pcap_len
        
        # Vérifier d'autres protocoles
        if hasattr(packet, 'arp'):
            proto_flow_dict['ARP'] += pcap_len
        elif hasattr(packet, 'icmp') or hasattr(packet, 'icmpv6'):
            proto_flow_dict['ICMP'] += pcap_len
        elif hasattr(packet, 'dns'):
            proto_flow_dict['DNS'] += pcap_len
    
    # Reset la capture
    capture.reset()
    
    return proto_flow_dict

# Statistiques sur les protocoles ayant le plus de trafic
def most_flow_statistic(capture, PD):
    """
    Identifie les protocoles qui génèrent le plus de trafic
    """
    most_flow_dict = collections.defaultdict(int)
    
    # Reset la capture
    capture.reset()
    
    # On utilise PD pour décoder les paquets
    packets_data = PD.decode_all_packets(capture)
    
    for packet_data in packets_data.values():
        protocol = packet_data['Protocol']
        packet_len = packet_data['len']
        most_flow_dict[protocol] += packet_len
    
    # Reset la capture
    capture.reset()
    
    return most_flow_dict