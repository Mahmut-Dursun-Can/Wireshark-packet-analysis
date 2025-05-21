#dashboard.py
import matplotlib.pyplot as plt
from collections import Counter
from capture import capture_pcap
from processor import extract_network_data
from collections import defaultdict
from collections import Counter

def calculate_ip_pairs(network_data):
    ip_pair_counter = Counter()
    
    for packet in network_data:
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if src_ip and dst_ip:
            pair = (src_ip, dst_ip)
            ip_pair_counter[pair] += 1

    return ip_pair_counter

def calculate_ip_activity(network_data):
    ip_counter = defaultdict(int)

    for packet in network_data:
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')

        if src_ip:
            ip_counter[src_ip] += 1
        if dst_ip:
            ip_counter[dst_ip] += 1

    return dict(ip_counter)

# Byte değerini daha anlamlı birimlere dönüştüren fonksiyon
def bytes_to_human_readable(byte_size):
    if byte_size < 1024:
        return f"{byte_size} B"
    elif byte_size < 1024**2:
        return f"{byte_size / 1024:.2f} KB"
    elif byte_size < 1024**3:
        return f"{byte_size / 1024**2:.2f} MB"
    else:
        return f"{byte_size / 1024**3:.2f} GB"

# Protokol başına veri boyutunun ne kadar "yüksek" olduğunu gösteren bir hız analizi yapabiliriz.
def calculate_protocol_speeds(network_data):
    # Her protokol için toplam veri boyutlarını hesapla
    protokol_veri_boyutlari = {}
    protokol_sayilari = Counter()

    for packet in network_data:
        protocol = packet['protocol']
        size = packet['size']
        protokol_sayilari[protocol] += 1
        if protocol in protokol_veri_boyutlari:
            protokol_veri_boyutlari[protocol] += size
        else:
            protokol_veri_boyutlari[protocol] = size

    # Veri boyutlarını protokol sayısına bölelim (bu, her protokol için "hızı" temsil eder)
    protocol_speeds = {}
    for protocol, total_size in protokol_veri_boyutlari.items():
        packet_count = protokol_sayilari[protocol]
        protocol_speeds[protocol] = total_size / packet_count if packet_count > 0 else 0

    return protocol_speeds, protokol_sayilari, protokol_veri_boyutlari

def visualize_protocol_usage(file_path,start_time, end_time):
    capture = capture_pcap(file_path, start_time=start_time, end_time=end_time)
    network_data = extract_network_data(capture)

    # Protokol hızı ve veri boyutlarını hesapla
    protocol_speeds, protokol_sayilari, protokol_veri_boyutlari = calculate_protocol_speeds(network_data)

    # Protokoller ve veri boyutları sıralandı
    sorted_protocols = sorted(protokol_sayilari.items(), key=lambda x: x[1], reverse=True)
    sorted_data_sizes = {protocol: protokol_veri_boyutlari.get(protocol, 0) for protocol, _ in sorted_protocols}

    # Figür ve eksenler oluşturuluyor (2x3 grid)
    fig, ax = plt.subplots(2, 3, figsize=(14, 7))  # Daha geniş görünüm

    # 1. Protokol Sayı Dağılımı (Pasta Grafiği)
    ax[0, 0].pie(protokol_sayilari.values(), labels=protokol_sayilari.keys(), autopct='%1.1f%%', startangle=140)
    ax[0, 0].set_title('Protokol Sayı Dağılımı')

    # 2. Protokol Başına Veri Boyutu (Çubuk Grafiği)
    bars = ax[0, 1].bar(sorted_data_sizes.keys(), sorted_data_sizes.values(), color='skyblue')
    ax[0, 1].set_title('Protokol Başına Veri Boyutu (bytes)')
    ax[0, 1].set_ylabel('Veri Boyutu (bytes)')
    ax[0, 1].set_xticklabels(sorted_data_sizes.keys(), rotation=45, ha='right')

    for bar in bars:
        height = bar.get_height()
        label = bytes_to_human_readable(height)
        ax[0, 1].text(bar.get_x() + bar.get_width() / 2, height, label, ha='center', va='bottom', fontsize=10)

    # 3. Protokol Başına Ortalama Yük (Çubuk Grafiği)
    protocols = list(protocol_speeds.keys())
    speeds = list(protocol_speeds.values())
    ax[0, 2].bar(protocols, speeds, color='lightcoral')
    ax[0, 2].set_title('Protokol Başına Ortalama Veri Yükü')
    ax[0, 2].set_ylabel('Ortalama Veri Yükü (bytes/paket)')
    ax[0, 2].set_xlabel('Protokol')
    ax[0, 2].tick_params(axis='x', rotation=45)

    # 4. Protokol Sayıları (Çubuk Grafiği)
    ax[1, 0].bar(protokol_sayilari.keys(), protokol_sayilari.values(), color='lightgreen')
    ax[1, 0].set_title('Protokol Başına Paket Sayısı')
    ax[1, 0].set_ylabel('Paket Sayısı')
    ax[1, 0].set_xticklabels(protokol_sayilari.keys(), rotation=45, ha='right')

    # 5. En Yoğun IP Adresleri (Çubuk Grafiği)
    ip_activity = calculate_ip_activity(network_data)
    sorted_ips = sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:10]  # En yoğun 10 IP

    ips, counts = zip(*sorted_ips)
    bars = ax[1, 1].bar(ips, counts, color='orchid')
    ax[1, 1].set_title('En Yoğun IP Adresleri')
    ax[1, 1].set_ylabel('Paket Sayısı')
    ax[1, 1].set_xlabel('IP Adresi')
    ax[1, 1].set_xticklabels(ips, rotation=45, ha='right')

    for bar in bars:
        height = bar.get_height()
        ax[1, 1].text(bar.get_x() + bar.get_width() / 2, height, f'{int(height)}', ha='center', va='bottom', fontsize=9)

    # 6. Boş bırakabiliriz veya toplam paket sayısını yazdırabiliriz
    # 6. En Yoğun IP Konuşma Çiftleri (Çubuk Grafiği)
    ip_pairs = calculate_ip_pairs(network_data)
    sorted_pairs = ip_pairs.most_common(10)  # En yoğun 10 çift

    pair_labels = [f"{src} → {dst}" for (src, dst), _ in sorted_pairs]
    pair_counts = [count for _, count in sorted_pairs]

    bars = ax[1, 2].bar(pair_labels, pair_counts, color='goldenrod')
    ax[1, 2].set_title('En Yoğun IP Konuşma Çiftleri')
    ax[1, 2].set_ylabel('Paket Sayısı')
    ax[1, 2].set_xticklabels(pair_labels, rotation=45, ha='right')

    for bar in bars:
        height = bar.get_height()
        ax[1, 2].text(bar.get_x() + bar.get_width() / 2, height, f'{int(height)}', 
                      ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig('png/dashboard.png')

