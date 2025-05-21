import ipaddress
import pyshark
import networkx as nx
import matplotlib.pyplot as plt
from collections import Counter
from capture import capture_pcap
from processor import extract_network_data
from dashboard import visualize_protocol_usage  # Bunu en üste ekle
from syn_ack_analyzer import analyze_syn_ack
from Icmp import icmp_analyze
from udp import udp_analyze
import folium
import requests
import webbrowser
import socket


# Bilinen sunucu portları
sunucu_portlari = {
    20, 21,      # FTP
    22,          # SSH
    23,          # Telnet
    25, 465, 587,# SMTP (mail gönderme)
    53,          # DNS
    67, 68,      # DHCP
    69,          # TFTP
    80, 443,     # HTTP, HTTPS
    110, 995,    # POP3, POP3S
    143, 993,    # IMAP, IMAPS
    161, 162,    # SNMP
    389, 636,    # LDAP
    445,         # SMB
    3306,        # MySQL
    5432,        # PostgreSQL
    1433, 1434,  # MS SQL
    1521,        # Oracle
    3389,        # RDP
    5900,        # VNC
    8080, 8443   # Alternatif HTTP/HTTPS
}

def geoip_bilgisi(ip):
    domain = None
    # Ters DNS lookup ile domain almayı dene
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        # Eğer alınamazsa domain None kalır
        domain = None

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        if r.get('status') == 'success':
            print(f"[+] {ip} → {r['city']}, {r['country']}", end='')
            if domain:
                print(f" (domain: {domain})")
            else:
                print()
            return {
                "ip": ip,
                "domain": domain,
                "lat": r['lat'],
                "lon": r['lon'],
                "city": r['city'],
                "country": r['country']
            }
    except Exception as e:
        print(f"[!] {ip} için hata: {e}")

    return None


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

# Harita oluştur
def harita_olustur(geoip_listesi, dosya_adi="harita.html"):
    harita = folium.Map(location=[20, 0], zoom_start=2)

    for veri in geoip_listesi:
        folium.Marker(
            location=[veri["lat"], veri["lon"]],
            popup=f"{veri['ip']},{veri['domain']} - {veri['city']}, {veri['country']}"
        ).add_to(harita)

    harita.save(dosya_adi)
    print(f"[✔] Harita oluşturuldu: {dosya_adi}")
    webbrowser.open(dosya_adi)


def main(file_path,start_time, end_time):
    ssl_keylog_path = 'C:/Users/cmahm/sslkeylog.log'

    # 1. Yakalama ve veri işleme
    cap = capture_pcap(file_path, sslkeylog_file=ssl_keylog_path, start_time=start_time, end_time=end_time)
    network_data = extract_network_data(cap)

    # 2. Network graph görselleştirme
    G = nx.Graph()
    baglanti_sayilari = Counter()

    for pkt in network_data:
        src, dst = pkt['src_ip'], pkt['dst_ip']
        prot, size = pkt['protocol'], pkt['size']
        dst_port = int(pkt.get('dst_port') or 0)

        G.add_edge(src, dst, weight=size, protocol=prot)
        baglanti_sayilari[(src, dst)] += 1
        print(f"{src} ---- {dst} ---- {prot}")

        if dst_port in sunucu_portlari:
            G.nodes[dst]['type'] = 'sunucu'
            G.nodes[src]['type'] = 'istemci'
        else:
            G.nodes[dst]['type'] = 'istemci'
            G.nodes[src]['type'] = 'sunucu'

    pos = nx.spring_layout(G, k=3.0, iterations=50, seed=43)
    node_colors = ['red' if G.nodes[n].get('type')=='sunucu' else 'lightgreen' if G.nodes[n].get('type')=='istemci' else 'gray' for n in G.nodes()]

    plt.figure(figsize=(12, 8))
    nx.draw_networkx_nodes(G, pos, node_size=1000, node_color=node_colors, alpha=0.9)
    edge_widths = [baglanti_sayilari.get(e, baglanti_sayilari.get((e[1], e[0]),1))*0.5 for e in G.edges()]
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.7)
    nx.draw_networkx_labels(G, pos, font_size=10)

    labels = {e: f"{G.edges[e]['protocol']}\nBS:{baglanti_sayilari.get(e,baglanti_sayilari.get((e[1],e[0]),1))}" for e in G.edges()}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_size=8)

    plt.legend(handles=[
        plt.Line2D([0],[0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Sunucu'),
        plt.Line2D([0],[0], marker='o', color='w', markerfacecolor='lightgreen', markersize=10, label='İstemci'),
        plt.Line2D([0],[0], marker='o', color='w', markerfacecolor='black', markersize=10, label='BS: Bağlantı Sayısı')
    ], loc='upper right')
    plt.title('Network Haritası', fontsize=14)
    plt.axis('off')
    plt.savefig('png/network_map.png')
    plt.close()


    # 3. Protokol ve SYN-ACK analizleri
    visualize_protocol_usage(file_path,start_time, end_time)
    analyze_syn_ack(file_path,start_time, end_time)
    udp_analyze(file_path,start_time, end_time)
    icmp_analyze(file_path,start_time, end_time)
    # 4. Harita için IP seti oluşturma
    ip_set = { ip for pkt in network_data for ip in (pkt['src_ip'], pkt['dst_ip']) }
    ipler = [ip for ip in ip_set if is_valid_ip(ip) and not (ip.startswith('10.') or ip.startswith('192.') or ip.startswith('172.'))]

    # 5. GeoIP ve harita oluşturma
    geoip_listesi = [geoip_bilgisi(ip) for ip in ipler]
    geoip_listesi = [g for g in geoip_listesi if g]
    harita_olustur(geoip_listesi)

if __name__ == '__main__':
    main(file_path=None,start_time=None, end_time=None)