from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QFileDialog,
    QLabel, QVBoxLayout, QWidget, QProgressBar, QLineEdit, QHBoxLayout,QSizePolicy
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import sys
from analyzer_main import main


class NetworkAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ağ Trafiği Analiz Aracı")
        self.setGeometry(100, 100, 900, 600)  # Genişliği artırdım
        self.setStyleSheet("background-color: #f4f4f9; font-family: Arial, sans-serif;")

        self.label = QLabel("Bir pcapng dosyası seçin, süreyi belirleyin ve analizi başlatın.", self)
        self.label.setFixedWidth(200)
        self.label.setWordWrap(True)
        self.label.setStyleSheet("font-size: 14px; color: #333;")

        self.button_browse = QPushButton("PCAP Dosyası Seç", self)
        self.button_browse.setFixedWidth(200)
        self.button_browse.setStyleSheet("background-color: #4CAF50; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")
        self.button_browse.clicked.connect(self.dosya_sec)

        self.start_input = QLineEdit(self)
        self.start_input.setPlaceholderText("Başlangıç süresi (saniye)")
        self.start_input.setFixedWidth(150)

        self.end_input = QLineEdit(self)
        self.end_input.setPlaceholderText("Bitiş süresi (saniye)")
        self.end_input.setFixedWidth(150)




        self.button_show_graph = QPushButton("Ip Grafiği", self)
        self.button_show_graph.setFixedWidth(200)
        self.button_show_graph.clicked.connect(lambda: self.grafik_goster('png/network_map.png'))
        self.button_show_graph.setStyleSheet("background-color:rgb(153, 204, 255) ; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")


        self.button_dashboard=QPushButton("Analiz",self)
        self.button_dashboard.setFixedWidth(200)
        self.button_dashboard.clicked.connect(lambda: self.grafik_goster('png/dashboard.png'))
        self.button_dashboard.setStyleSheet("background-color:rgb(153, 204, 255) ; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")
    

        self.button_synack=QPushButton("Syn-Ack Paketleri",self)
        self.button_synack.setFixedWidth(200)
        self.button_synack.clicked.connect(lambda: self.grafik_goster('png/syn_ack.png'))
        self.button_synack.setStyleSheet("background-color:rgb(153, 204, 255) ; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")


        self.button_udp=QPushButton("UDP Paketleri",self)
        self.button_udp.setFixedWidth(200)
        self.button_udp.clicked.connect(lambda: self.grafik_goster('png/udp.png'))
        self.button_udp.setStyleSheet("background-color:rgb(153, 204, 255) ; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")


        self.button_icmp=QPushButton("Icmp Paketleri",self)
        self.button_icmp.setFixedWidth(200)
        self.button_icmp.clicked.connect(lambda: self.grafik_goster('png/icmp.png'))
        self.button_icmp.setStyleSheet("background-color:rgb(153, 204, 255) ; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")

        self.button_analyze = QPushButton("Analizi Başlat", self)
        self.button_analyze.setFixedWidth(200)
        self.button_analyze.setStyleSheet("background-color: #2196F3; color: white; padding: 6px 3px; border-radius: 5px; font-size: 14px;")
        self.button_analyze.clicked.connect(self.analiz_baslat)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)

        self.graph_label = QLabel(self)
        self.graph_label.setStyleSheet("border: 1px solid #ccc; background-color: white;")
        self.graph_label.setFixedSize(1600,1080)
        
        # Sol taraftaki widget ve layout
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.label)
        left_layout.addWidget(self.button_analyze)
        left_layout.addWidget(self.button_browse)
        left_layout.addWidget(self.start_input) 
        left_layout.addWidget(self.end_input)
        left_layout.addWidget(self.progress_bar)
        left_layout.addWidget(self.button_analyze)
        left_layout.addWidget(self.button_synack)
        left_layout.addWidget(self.button_icmp)
        left_layout.addWidget(self.button_udp)
        left_layout.addWidget(self.button_show_graph)
        left_layout.addWidget(self.button_dashboard)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.button_analyze)
        button_layout.addWidget(self.button_synack)
        button_layout.addWidget(self.button_icmp)
        button_layout.addWidget(self.button_udp)
        button_layout.addWidget(self.button_show_graph)
        button_layout.addWidget(self.button_dashboard)

        left_layout.addLayout(button_layout)
        left_layout.addStretch()

        # Ana yatay layout: sol - sağ
        main_layout = QHBoxLayout()
        left_widget = QWidget()
        main_layout.setContentsMargins(0, 0, 0, 0)  # Sol, üst, sağ, alt boşlukları sıfırla

        left_widget.setLayout(left_layout)
        main_layout.addWidget(left_widget)
        left_widget.setMaximumWidth(200)
        left_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.graph_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        main_layout.addWidget(self.graph_label, 3)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.pcap_path = None

    def dosya_sec(self):
        path, _ = QFileDialog.getOpenFileName(self, "PCAP Dosyası Seç", "", "PCAP Files (*.pcapng *.pcap)")
        if path:
            self.pcap_path = path
            self.label.setText(f"Seçilen dosya: {path}")

    def analiz_baslat(self):
        if not self.pcap_path:
            self.label.setText("Lütfen önce bir dosya seçin.")
            return

        try:
            start_time = float(self.start_input.text()) if self.start_input.text() else None
            end_time = float(self.end_input.text()) if self.end_input.text() else None
        except ValueError:
            self.label.setText("Lütfen geçerli başlangıç/bitiş süresi girin (sayı formatında).")
            return

        self.progress_bar.setVisible(True)
        self.button_analyze.setEnabled(False)
        self.label.setText("Analiz başlatılıyor...")

        try:
            main(self.pcap_path, start_time=start_time, end_time=end_time)
            self.label.setText("Analiz tamamlandı!")
        except Exception as e:
            self.label.setText(f"Hata oluştu: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.button_analyze.setEnabled(True)

   
    def grafik_goster(self, grafik_dosyasi):
        pixmap = QPixmap(grafik_dosyasi)
        if pixmap.isNull():
            self.label.setText(f"Görsel yüklenemedi: {grafik_dosyasi} bulunamadı.")
            return
        self.graph_label.setPixmap(pixmap.scaled(
            self.graph_label.width(), self.graph_label.height(),
            Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
        self.label.setText(f"{grafik_dosyasi} yüklendi.")



def run_gui():
    app = QApplication(sys.argv)
    window = NetworkAnalyzerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_gui()
