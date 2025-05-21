import matplotlib.pyplot as plt
import seaborn as sns
from capture import capture_pcap
from collections import defaultdict

def udp_analyze(file_path,start_time, end_time):
    capture = capture_pcap(file_path,start_time=start_time, end_time=end_time)
    
    # UDP paketleri için filtreleme
    packet_count = 0
    ip_counter = {}
    
    for packet in capture:
        if 'UDP' in packet:  # UDP protokolüne sahip paketleri kontrol et
            packet_count += 1
            if 'IP' in packet:  # IP katmanı var mı?
                src_ip = packet.ip.src
            elif 'IPv6' in packet:  # IPv6 var mı?
                src_ip = packet.ipv6.src
            else:
                continue  # IP veya IPv6 katmanı yoksa paketi atla
                
            ip_counter[src_ip] = ip_counter.get(src_ip, 0) + 1
    
    # UDP paketlerinin analizini yazdır
    print(f"Toplam UDP paketi: {packet_count}")
    print("En çok UDP paketi gönderen IP adresleri:")
    # En çok paket gönderen IP'leri göster
    ip_items = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in ip_items:
        print(f"{ip}: {count} paket")

    # Seaborn ile görselleştirme
    ip_list = [item[0] for item in ip_items]
    count_list = [item[1] for item in ip_items]

    # Seaborn bar plot
    plt.figure(figsize=(10, 6))
    sns.barplot(x=ip_list, y=count_list, palette='viridis')
    plt.title('En Çok UDP Paket Gönderen IP Adresleri')
    plt.xlabel('IP Adresi')
    plt.ylabel('Gönderilen UDP Paket Sayısı')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('png/udp.png')

