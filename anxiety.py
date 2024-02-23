from PyQt5.QtWidgets import (
    QMessageBox, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
    QTextEdit, QApplication, QWidget, QMainWindow, QPlainTextEdit, QSplitter
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import requests
from urllib.parse import urljoin
import time
import threading  
import subprocess  
import signal  

class WorkerThread(QThread):
    finished = pyqtSignal(list)

    def __init__(self, url, dirfiles):
        super().__init__()
        self.url = url
        self.dirfiles = dirfiles

    def run(self):
        all_results = []
        vuln_results = []

        for file in self.dirfiles:
            scan_url = urljoin(self.url, f"{file.strip()}")
            response = requests.get(scan_url)

            if response.status_code == 200:
                vuln_results.append(f"Kerentanan ditemukan pada URL: {scan_url}")
            else:
                all_results.append(f"Kerentanan tidak ditemukan pada URL: {scan_url}")

            time.sleep(0.5)  

        self.finished.emit([all_results, vuln_results])

class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Anxiety - Proyek untuk Pengungkapan Kerentanan Aplikasi Web dengan Pendekatan Black Box (Version 1.1)')
        self.setGeometry(100, 100, 1080, 720)
        self.setWindowIcon(QIcon('assets/icon.ico'))

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        layout = QVBoxLayout()
        self.centralWidget.setLayout(layout)

        tabWidget = QTabWidget()
        layout.addWidget(tabWidget)

        # Tab untuk Pengungkapan Informasi
        infoTab = QWidget()
        infoLayout = QVBoxLayout()
        infoTab.setLayout(infoLayout)

        # URL
        self.infoUrlLineEdit = QLineEdit()
        infoLayout.addWidget(QLabel('URL:'))
        infoLayout.addWidget(self.infoUrlLineEdit)

        # Mulai Pemeriksaan Pengungkapan Informasi
        self.infoScanButton = QPushButton('Mulai untuk Melakukan Pemeriksaan Pengungkapan Informasi')
        self.infoScanButton.setStyleSheet('background-color: green; color: white;')
        self.infoScanButton.clicked.connect(self.start_pemeriksaan)
        infoLayout.addWidget(self.infoScanButton)

        # Splitter untuk hasil pengungkapan informasi
        self.infoSplitter = QSplitter(Qt.Horizontal)

        # Kolom result untuk semua percobaan URL
        self.infoResultAllTextEdit = QTextEdit()
        self.infoResultAllTextEdit.setReadOnly(True)
        self.infoSplitter.addWidget(self.infoResultAllTextEdit)

        # Kolom result untuk kerentanan yang ditemukan
        self.infoResultVulnTextEdit = QTextEdit()
        self.infoResultVulnTextEdit.setReadOnly(True)
        self.infoSplitter.addWidget(self.infoResultVulnTextEdit)

        infoLayout.addWidget(self.infoSplitter)

        # Tambahkan tab ke widget tab
        tabWidget.addTab(infoTab, 'Pengungkapan Informasi')

        # Tab untuk Pembajakan Klik
        clickjackingTab = QWidget()
        clickjackingLayout = QVBoxLayout()
        clickjackingTab.setLayout(clickjackingLayout)

        self.clickjackingUrlLineEdit = QLineEdit()
        self.clickjackingResultTextEdit = QTextEdit()

        clickjackingScanButton = QPushButton('Mulai untuk Melakukan Pemeriksaan Pembajakan Klik')
        clickjackingScanButton.setStyleSheet('background-color: green; color: white;')
        clickjackingScanButton.clicked.connect(self.pembajakan_klik)

        clickjackingLayout.addWidget(QLabel('URL:'))
        clickjackingLayout.addWidget(self.clickjackingUrlLineEdit)
        clickjackingLayout.addWidget(clickjackingScanButton)
        clickjackingLayout.addWidget(self.clickjackingResultTextEdit)

        # Tambahkan tab Clickjacking ke widget tab
        tabWidget.addTab(clickjackingTab, 'Pembajakan Klik')

        # Tab untuk Pengekstraksian Tautan
        linkExtractionTab = QWidget()
        linkExtractionLayout = QVBoxLayout()
        linkExtractionTab.setLayout(linkExtractionLayout)

        self.linkExtractionUrlLineEdit = QLineEdit()
        self.linkExtractionResultTextEdit = QTextEdit()

        linkExtractionScanButton = QPushButton('Mulai untuk Melakukan Pengekstraksian Tautan')
        linkExtractionScanButton.setStyleSheet('background-color: green; color: white;')
        linkExtractionScanButton.clicked.connect(self.pengekstraksian_tautan)

        linkExtractionLayout.addWidget(QLabel('URL:'))
        linkExtractionLayout.addWidget(self.linkExtractionUrlLineEdit)
        linkExtractionLayout.addWidget(linkExtractionScanButton)
        linkExtractionLayout.addWidget(self.linkExtractionResultTextEdit)

        # Tambahkan tab Pengekstraksian Tautan ke widget tab
        tabWidget.addTab(linkExtractionTab, 'Pengekstraksian Tautan')

        # Tab untuk Pemeriksaan Header HTTP
        headerCheckTab = QWidget()
        headerCheckLayout = QVBoxLayout()
        headerCheckTab.setLayout(headerCheckLayout)

        self.headerCheckUrlLineEdit = QLineEdit()
        self.headerCheckResultTextEdit = QTextEdit()

        headerCheckScanButton = QPushButton('Mulai untuk Melakukan Pemeriksaan Header HTTP')
        headerCheckScanButton.setStyleSheet('background-color: green; color: white;')
        headerCheckScanButton.clicked.connect(self.pemeriksaan_header_http)

        headerCheckLayout.addWidget(QLabel('URL:'))
        headerCheckLayout.addWidget(self.headerCheckUrlLineEdit)
        headerCheckLayout.addWidget(headerCheckScanButton)
        headerCheckLayout.addWidget(self.headerCheckResultTextEdit)

        # Tambahkan tab Pemeriksaan Header HTTP ke widget tab
        tabWidget.addTab(headerCheckTab, 'Pemeriksaan Header HTTP')

        # Tambahkan GUI SQLMap ke tab baru
        sqlMapTab = QWidget()
        sqlMapLayout = QVBoxLayout()
        sqlMapTab.setLayout(sqlMapLayout)

        # SQLMap URL
        self.sqlMapUrlLabel = QLabel('URL:')
        self.sqlMapUrlInput = QLineEdit(self)
        sqlMapLayout.addWidget(self.sqlMapUrlLabel)
        sqlMapLayout.addWidget(self.sqlMapUrlInput)

        # Tombol untuk menjalankan SQLMap
        self.sqlMapRunButton = QPushButton('Mulai untuk Melakukan Pengungkapan Injeksi SQL')
        self.sqlMapRunButton.setStyleSheet('background-color: green; color: white;')
        self.sqlMapRunButton.clicked.connect(self.SQLMap)
        sqlMapLayout.addWidget(self.sqlMapRunButton)

        # Splitter untuk memisahkan terminal dan input
        sqlMapSplitter = QSplitter(self)
        sqlMapLayout.addWidget(sqlMapSplitter)

        # Terminal untuk menampilkan output SQLMap
        self.sqlMapTerminal = QPlainTextEdit(self)
        self.sqlMapTerminal.setReadOnly(True)
        sqlMapSplitter.addWidget(self.sqlMapTerminal)

        # Tambahkan tab SQLMap ke widget tab
        tabWidget.addTab(sqlMapTab, 'Pengungkapan Injeksi SQL')

    def start_pemeriksaan(self):
        url = self.infoUrlLineEdit.text().strip('/')
        dirfiles = ['.env', '.git', 'storage/logs/laravel.log', 'app/etc/local.xml', 'npm-debug.log',
                    'debug/pprof', '.hg', '.php_cs.cache', 'phpinfo.php', 'webadmin.php',
                    'backup', 'doc', 'docs', 'robots.txt', 'readme.html', 'readme.txt', 'changelog.txt',
                    '.htaccess', 'Global.asa', 'Global.asax', 'elmah.axd', 'errorlog.axd', 'trace.axd']

        # Buat thread untuk pemeriksaan berjalan di background
        self.worker_thread = WorkerThread(url, dirfiles)
        self.worker_thread.finished.connect(self.handle_pemeriksaan_result)
        self.worker_thread.start()

    def handle_pemeriksaan_result(self, result):
        all_results, vuln_results = result
        self.infoResultAllTextEdit.setPlainText('\n'.join(all_results))
        self.infoResultVulnTextEdit.setPlainText('\n'.join(vuln_results))

    def pembajakan_klik(self):
        url = self.clickjackingUrlLineEdit.text()
        response = requests.get(url)
        headers = response.headers

        if 'X-Frame-Options' in headers:
            self.clickjackingResultTextEdit.setPlainText('Situs ini dilindungi oleh X-Frame-Options header, tidak rentan terhadap clickjacking.')
        elif 'Content-Security-Policy' in headers and 'frame-ancestors' in headers['Content-Security-Policy']:
            self.clickjackingResultTextEdit.setPlainText('Situs ini dilindungi oleh Content Security Policy frame-ancestors, tidak rentan terhadap clickjacking.')
        else:
            self.clickjackingResultTextEdit.setPlainText('Situs ini rentan terhadap clickjacking.')

            # Menunjukkan alasan mengapa situs rentan terhadap clickjacking
            if 'X-Frame-Options' not in headers:
                self.clickjackingResultTextEdit.append('Alasan: Header X-Frame-Options tidak diset.')
            elif 'Content-Security-Policy' in headers and 'frame-ancestors' not in headers['Content-Security-Policy']:
                self.clickjackingResultTextEdit.append('Alasan: Header Content Security Policy frame-ancestors tidak diset.')

        if not response.ok:
            QMessageBox.critical(self, 'Error', 'Gagal mengambil halaman web. Pastikan URL valid dan situs dapat diakses.')

    def pengekstraksian_tautan(self):
        url = self.linkExtractionUrlLineEdit.text()
        api_url = f"https://api.hackertarget.com/pagelinks/?q={url}"
        response = requests.get(api_url)

        if response.status_code == 200:
            links = response.text.splitlines()
            self.linkExtractionResultTextEdit.setPlainText('\n'.join(links))
        else:
            self.linkExtractionResultTextEdit.setPlainText('Gagal mengekstrak tautan. Pastikan URL valid dan situs dapat diakses.')

    def pemeriksaan_header_http(self):
        url = self.headerCheckUrlLineEdit.text()
        response = requests.head(url)

        headers = response.headers
        self.headerCheckResultTextEdit.setPlainText('\n'.join([f"{header}: {headers[header]}" for header in headers]))

        if not response.ok:
            QMessageBox.critical(self, 'Error', 'Gagal mengambil header. Pastikan URL valid dan situs dapat diakses.')

    def SQLMap(self):
        target_url = self.sqlMapUrlInput.text()
        sqlmap_cmd = f'sqlmap {target_url} --dump --batch'
        
        # Menjalankan SQLMap dalam terminal terpisah di Windows
        subprocess.Popen(['start', 'powershell', '-NoExit', '-Command', sqlmap_cmd], shell=True)

    def SQLMapThread(self, cmd):
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while process.poll() is None:
            output = process.stdout.readline()
            self.sqlMapTerminal.insertPlainText(output)
            QApplication.processEvents()
            time.sleep(0.1)

    def closeEvent(self, event):
        # Menangani penutupan aplikasi dengan aman
        if hasattr(self, 'sqlmap_thread') and self.sqlmap_thread.is_alive():
            # Mengirim sinyal SIGINT ke proses SQLMap untuk memberhentikannya sebelum menutup aplikasi
            process = self.sqlmap_thread._target
            process.send_signal(signal.SIGINT)
            process.communicate()
            self.sqlmap_thread.join()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec_())
