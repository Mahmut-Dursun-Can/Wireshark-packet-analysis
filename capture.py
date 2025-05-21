import pyshark
from datetime import datetime


def capture_pcap(file_path,sslkeylog_file=None,start_time=None,end_time=None):
    # PCAP dosyasını aç
    capture = pyshark.FileCapture(file_path, tshark_path=r"D:/Wireshark/tshark.exe", keep_packets=False)

    # SSL keylog dosyasının entegrasyonu
    if sslkeylog_file:
        capture.keylog_file = sslkeylog_file
        print(f"SSL Keylog dosyası {sslkeylog_file} başarıyla entegre edildi.")

    # Eğer saniye filtresi verilmediyse, olduğu gibi döndür
    if start_time is None or end_time is None:
        return capture

    # Zaman filtreli paket listesi oluştur
    paket_listesi = []

    ilk_paket_zamani = None

    for packet in capture:
        paket_zamani = packet.sniff_time  # datetime formatında

        if ilk_paket_zamani is None:
            ilk_paket_zamani = paket_zamani  # İlk paketin zamanı başlangıç olur

        # Kaç saniye geçtiğini hesapla
        gecen_saniye = (paket_zamani - ilk_paket_zamani).total_seconds()

        # Zaman aralığında olup olmadığını kontrol et
        if start_time <= gecen_saniye <= end_time:
            paket_listesi.append(packet)

        # Eğer zamanı geçtiyse döngüden çık (erken çıkış)
        if gecen_saniye > end_time:
            break

    capture.close()
    return paket_listesi
