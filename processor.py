def extract_network_data(capture):
    network_data = []

    for packet in capture:
        try:
            # ARP özel
            if 'ARP' in packet:
                src_ip = packet.arp.psrc
                dst_ip = packet.arp.pdst
                src_port_val = 0
                dst_port_val = 0
                proto = 'ARP'

            elif 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                size = int(packet.length)

                src_port_val = None
                dst_port_val = None
                proto = 'Unknown'

                # TCP Protokolleri
                if 'TCP' in packet:
                    src_port_val = int(packet.tcp.srcport)
                    dst_port_val = int(packet.tcp.dstport)

                    port_list = [src_port_val, dst_port_val]

                    if 'TLS' in packet or 443 in port_list:
                        proto = 'TLS/HTTPS'
                    elif 80 in port_list:
                        proto = 'HTTP'
                    elif 20 in port_list or 21 in port_list:
                        proto = 'FTP'
                    elif 22 in port_list:
                        proto = 'SSH'
                    elif 23 in port_list:
                        proto = 'Telnet'
                    elif 25 in port_list:
                        proto = 'SMTP'
                    elif 110 in port_list:
                        proto = 'POP3'
                    elif 143 in port_list:
                        proto = 'IMAP'
                    elif 389 in port_list:
                        proto = 'LDAP'
                    elif 445 in port_list:
                        proto = 'SMB'
                    elif 3389 in port_list:
                        proto = 'RDP'
                    else:
                        proto = 'TCP'

                # UDP Protokolleri
                elif 'UDP' in packet:
                    src_port_val = int(packet.udp.srcport)
                    dst_port_val = int(packet.udp.dstport)

                    port_list = [src_port_val, dst_port_val]

                    if 53 in port_list:
                        proto = 'DNS'
                    elif 67 in port_list or 68 in port_list:
                        proto = 'DHCP'
                    elif 69 in port_list:
                        proto = 'TFTP'
                    elif 123 in port_list:
                        proto = 'NTP'
                    elif 161 in port_list or 162 in port_list:
                        proto = 'SNMP'
                    elif 520 in port_list:
                        proto = 'RIP'
                    else:
                        proto = 'UDP'

                # ICMP Protokolü
                elif 'ICMP' in packet:
                    proto = 'ICMP'
                    src_port_val = None
                    dst_port_val = None

                # IGMP Protokolü
                elif 'IGMP' in packet:
                    proto = 'IGMP'
                    src_port_val = None
                    dst_port_val = None

                # Bilinmeyenler
                else:
                    proto = 'Unknown'

                # Listeye ekle
                network_data.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port_val,
                    'dst_port': dst_port_val,
                    'protocol': proto,
                    'size': size
                })

        except AttributeError:
            continue

    return network_data
