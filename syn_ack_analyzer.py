import datetime
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
from capture import capture_pcap

def analyze_syn_ack(file_path,start_time, end_time):
    ssl_keylog_path = 'C:/Users/cmahm/sslkeylog.log'
    cap = capture_pcap(file_path,sslkeylog_file=ssl_keylog_path,start_time=start_time, end_time=end_time)

    timestamps = []
    ip_counter_per_second = defaultdict(Counter)

    def fix_timestamp(t):
        if t > 1e12:
            return int(t / 1e6)
        elif t > 1e10:
            return int(t / 1e3)
        else:
            return int(t)

    for pkt in cap:
        try:
            if 'TCP' in pkt:
                flags = int(pkt.tcp.flags, 16)
                if flags == 0x12:  # SYN-ACK
                    raw_time = float(pkt.sniff_timestamp)
                    fixed_time = fix_timestamp(raw_time)
                    timestamps.append(fixed_time)

                    # IP adresini say
                    src_ip = pkt.ip.src
                    ip_counter_per_second[fixed_time][src_ip] += 1

        except AttributeError:
            continue


    if not timestamps:
        print("❌ Hiç SYN-ACK paketi bulunamadı. Grafik çizilmiyor.")
        return

    count_per_second = Counter(timestamps)
    times = sorted(count_per_second)
    counts = [count_per_second[t] for t in times]

    readable_times = [datetime.datetime.fromtimestamp(t).strftime('%H:%M:%S') for t in times]

    plt.figure(figsize=(10, 5))
    bars = plt.bar(readable_times, counts, width=0.8, color='skyblue', edgecolor='black')

    for i, t in enumerate(times):
        ip_counts = ip_counter_per_second[t]
        ip_list = [f"{ip} ({cnt})" for ip, cnt in ip_counts.most_common(3)]  # En fazla 3 IP yaz
        ip_text = "\n".join(ip_list)

        if counts[i] > 100:
            bars[i].set_color('red')
        else:
            bars[i].set_color('skyblue')

        # IP’leri bar üstüne yaz
        plt.text(i, counts[i] + 0.5, ip_text, ha='center', fontsize=10, rotation=90)

    plt.title('SYN-ACK Paket Sayısı)', fontsize=14, fontweight='bold')
    plt.xlabel('Zaman (HH:MM:SS)', fontsize=12)
    plt.ylim(0, max(counts) + 35)
    plt.yticks(range(0, max(counts) + 36, 1))  # 0'dan max'a kadar 1 adımla


    plt.xticks(rotation=45)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('png/syn_ack.png')

    for t, c in zip(times, counts):
        if c > 100:
            readable = datetime.datetime.fromtimestamp(t).strftime('%H:%M:%S')
            print(f"🚩 DDoS Şüphesi: {readable} zamanında {c} SYN-ACK paketi!")
