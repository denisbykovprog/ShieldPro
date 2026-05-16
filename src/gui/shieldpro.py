import sys
import os
import ctypes
import threading
import time
import datetime
import json
import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Callable, List, Dict

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QLineEdit, QTextEdit,
    QProgressBar, QComboBox, QCheckBox, QGroupBox, QSystemTrayIcon, QMenu, QAction, QMessageBox,
    QFileDialog, QHeaderView, QSplitter, QFrame, QStatusBar, QToolBar, QDialog, QDialogButtonBox,
    QScrollArea, QListWidget, QListWidgetItem, QProgressDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QDateTime, QSettings, QSize
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QPainter, QBrush, QLinearGradient, QCursor

try:
    from PyQt5.QtWinExtras import QtWin
    QtWin.setWindowFramework(QWindowDXGI)
except:
    pass

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
DATA_DIR = os.path.join(BASE_DIR, "data")
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
LOGS_DIR = os.path.join(DATA_DIR, "logs")

for d in [SIGNATURES_DIR, QUARANTINE_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

SIGNATURES_FILE = os.path.join(SIGNATURES_DIR, "signatures.txt")
if not os.path.exists(SIGNATURES_FILE):
    with open(SIGNATURES_FILE, "w") as f:
        f.write("EICAR:58354f2150254041505b345c505a58353428505e\n")
        f.write("TestVirus:48656c6c6f576f726c64\n")

os.add_dll_directory(os.path.dirname(os.path.abspath(__file__)))

engine_lib = None
heuristic_lib = None
monitor_lib = None
updater_lib = None

def load_native_modules():
    global engine_lib, heuristic_lib, monitor_lib, updater_lib
    engine_lib = None
    heuristic_lib = None
    monitor_lib = None
    updater_lib = None

    def is_valid_dll(path):
        if not os.path.exists(path):
            return False
        try:
            with open(path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except:
            return False

    try:
        engine_path = os.path.join(MODULES_DIR, "engine.dll")
        if is_valid_dll(engine_path):
            engine_lib = ctypes.CDLL(engine_path)
            engine_lib.init_scanner.restype = ctypes.c_int
            engine_lib.init_scanner.argtypes = [ctypes.c_char_p]
            engine_lib.load_signatures.restype = ctypes.c_int
            engine_lib.load_signatures.argtypes = [ctypes.c_char_p]
            engine_lib.scan_file.restype = ctypes.c_int
            engine_lib.scan_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
            engine_lib.get_scanner_version.restype = ctypes.c_char_p
            engine_lib.get_signature_count.restype = ctypes.c_int
            engine_lib.compute_file_hash.restype = ctypes.c_int
            engine_lib.compute_file_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            engine_lib.init_scanner(None)
            engine_lib.load_signatures(SIGNATURES_FILE.encode())
            print("[ShieldPro] Engine module loaded")
    except Exception as e:
        print(f"[ShieldPro] Engine load error: {e}")

    try:
        heuristic_path = os.path.join(MODULES_DIR, "heuristic.dll")
        if os.path.exists(heuristic_path):
            heuristic_lib = ctypes.CDLL(heuristic_path)
            heuristic_lib.analyze_file.restype = ctypes.c_void_p
            heuristic_lib.get_module_version.restype = ctypes.c_char_p
            print("[ShieldPro] Heuristic module loaded")
    except Exception as e:
        print(f"[ShieldPro] Heuristic load error: {e}")

    try:
        monitor_path = os.path.join(MODULES_DIR, "monitor.dll")
        if os.path.exists(monitor_path):
            monitor_lib = ctypes.CDLL(monitor_path)
            monitor_lib.init_monitor.restype = ctypes.c_int
            monitor_lib.init_monitor.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
            monitor_lib.stop_monitor.restype = None
            monitor_lib.add_firewall_rule.restype = ctypes.c_int
            monitor_lib.add_firewall_rule.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
            monitor_lib.get_firewall_rules.restype = ctypes.c_int
            monitor_lib.clear_firewall_rules.restype = None
            monitor_lib.get_monitor_version.restype = ctypes.c_char_p
            monitor_lib.register_autostart.restype = ctypes.c_int
            monitor_lib.register_autostart.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            monitor_lib.unregister_autostart.restype = ctypes.c_int
            monitor_lib.check_usb_devices.restype = ctypes.c_int
            monitor_lib.block_autorun.restype = ctypes.c_int
            monitor_lib.get_connected_drives.restype = ctypes.c_int
            print("[ShieldPro] Monitor module loaded")
    except Exception as e:
        print(f"[ShieldPro] Monitor load error: {e}")

    try:
        updater_path = os.path.join(MODULES_DIR, "updater.dll")
        if os.path.exists(updater_path):
            updater_lib = ctypes.CDLL(updater_path)
            updater_lib.GetUpdaterVersion.restype = ctypes.c_char_p
            updater_lib.CheckForUpdates.restype = ctypes.c_char_p
            updater_lib.CheckForUpdates.argtypes = [ctypes.c_char_p]
            updater_lib.DownloadSignatures.restype = ctypes.c_char_p
            updater_lib.DownloadSignatures.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            updater_lib.GetUpdateStatus.restype = ctypes.c_char_p
            print("[ShieldPro] Updater module loaded")
    except Exception as e:
        print(f"[ShieldPro] Updater load error: {e}")

class PythonScanner:
    def __init__(self):
        self.signatures = {}
        self.load_signatures()

    def load_signatures(self):
        sig_file = os.path.join(SIGNATURES_DIR, "signatures.txt")
        if os.path.exists(sig_file):
            with open(sig_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line and not line.startswith('#'):
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            name, hex_sig = parts
                            try:
                                self.signatures[name] = bytes.fromhex(hex_sig)
                            except:
                                pass
        print(f"[ShieldPro] Loaded {len(self.signatures)} signatures (Python fallback)")

    def scan_file(self, filepath):
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'rb') as f:
                data = f.read(65536)
            for name, sig in self.signatures.items():
                if len(sig) <= len(data) and sig in data:
                    return name
            return None
        except:
            return None

python_scanner = None

def get_python_scanner():
    global python_scanner
    if python_scanner is None:
        python_scanner = PythonScanner()
    return python_scanner

class ScanThread(QThread):
    progress_signal = pyqtSignal(int, str, str)
    finished_signal = pyqtSignal(int, list)
    threat_found_signal = pyqtSignal(str, str, int)

    def __init__(self, scan_type, paths):
        super().__init__()
        self.scan_type = scan_type
        self.paths = paths
        self.running = True
        self.paused = False

    def run(self):
        results = []
        total_files = 0

        def scan_directory(path):
            nonlocal total_files
            try:
                for root, dirs, files in os.walk(path):
                    if not self.running:
                        return
                    while self.paused and self.running:
                        time.sleep(0.1)
                    for file in files:
                        if not self.running:
                            return
                        filepath = os.path.join(root, file)
                        total_files += 1
                        self.progress_signal.emit(total_files, filepath, "Scanning...")

                        threat_name_str = None
                        threat_type = 1
                        result = 0

                        if engine_lib:
                            try:
                                threat_name = ctypes.create_string_buffer(256)
                                threat_type_ct = ctypes.c_int(0)
                                result = engine_lib.scan_file(
                                    filepath.encode(),
                                    threat_name,
                                    256,
                                    ctypes.byref(threat_type_ct)
                                )
                                if result > 0:
                                    threat_name_str = threat_name.value.decode('utf-8', errors='ignore')
                            except:
                                pass

                        if not result or not threat_name_str:
                            ps = get_python_scanner()
                            threat_name_str = ps.scan_file(filepath)

                        if threat_name_str:
                            results.append((filepath, threat_name_str, threat_type))
                            self.threat_found_signal.emit(filepath, threat_name_str, threat_type)
            except Exception as e:
                print(f"Scan error: {e}")

        for path in self.paths:
            if os.path.isfile(path):
                total_files += 1
                self.progress_signal.emit(total_files, path, "Scanning...")
                threat_name_str = None
                threat_type = 1
                result = 0

                if engine_lib:
                    try:
                        threat_name = ctypes.create_string_buffer(256)
                        threat_type_ct = ctypes.c_int(0)
                        result = engine_lib.scan_file(
                            path.encode(),
                            threat_name,
                            256,
                            ctypes.byref(threat_type_ct)
                        )
                        if result > 0:
                            threat_name_str = threat_name.value.decode('utf-8', errors='ignore')
                    except:
                        pass

                if not result or not threat_name_str:
                    ps = get_python_scanner()
                    threat_name_str = ps.scan_file(path)

                if threat_name_str:
                    results.append((path, threat_name_str, threat_type))
                    self.threat_found_signal.emit(path, threat_name_str, threat_type)
            elif os.path.isdir(path):
                scan_directory(path)

        self.finished_signal.emit(len(results), results)

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

class ModernButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0078D7, stop:1 #0098FF);
                border: none;
                border-radius: 6px;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                font-size: 13px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #106EBE, stop:1 #0078D7);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005A9E, stop:1 #106EBE);
            }
            QPushButton:disabled {
                background: #555;
                color: #888;
            }
        """)

class StatusIndicator(QWidget):
    def __init__(self, status="protected", parent=None):
        super().__init__(parent)
        self.status = status
        self.setMinimumWidth(200)
        self.setMinimumHeight(60)

    def set_status(self, status):
        self.status = status
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        gradient = QLinearGradient(0, 0, self.width(), 0)
        if self.status == "protected":
            gradient.setColorAt(0, QColor("#2E7D32"))
            gradient.setColorAt(1, QColor("#4CAF50"))
            status_text = "Защита включена"
            icon = "🛡️"
        elif self.status == "warning":
            gradient.setColorAt(0, QColor("#F57C00"))
            gradient.setColorAt(1, QColor("#FF9800"))
            status_text = "Внимание"
            icon = "⚠️"
        else:
            gradient.setColorAt(0, QColor("#C62828"))
            gradient.setColorAt(1, QColor("#F44336"))
            status_text = "Защита отключена"
            icon = "⛔"

        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 10, 10)

        painter.setPen(Qt.white)
        font = QFont("Segoe UI", 14, QFont.Bold)
        painter.setFont(font)
        painter.drawText(50, 25, f"{icon} {status_text}")
        font_small = QFont("Segoe UI", 10)
        painter.setFont(font_small)
        painter.drawText(50, 42, f"ShieldPro v1.0.0 | {datetime.datetime.now().strftime('%H:%M')}")

class ShieldProGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_thread = None
        self.is_scanning = False
        self.is_protected = True
        self.threats_today = 0
        self.settings = QSettings("RuGuard", "ShieldPro")
        self.log_events = []
        self.scan_results = []
        self.quarantine_items = []
        self.firewall_rules = []
        self.init_ui()
        self.load_quarantine()
        self.load_log()
        load_native_modules()
        self.start_realtime_protection()
        self.tray_icon.show()

    def init_ui(self):
        self.setWindowTitle("ShieldPro - Антивирусная защита")
        self.setMinimumSize(1100, 750)
        self.setWindowFlags(Qt.Window | Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint)

        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#1E1E1E"))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor("#252526"))
        palette.setColor(QPalette.AlternateBase, QColor("#2D2D30"))
        palette.setColor(QPalette.ToolTipBase, QColor("#3E3E42"))
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor("#3E3E42"))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor("#0078D7"))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.create_header(main_layout)
        self.create_tabs(main_layout)
        self.create_status_bar(main_layout)
        self.create_tray_icon()

    def create_header(self, layout):
        header = QFrame()
        header.setStyleSheet("background: #252526; border-bottom: 1px solid #3E3E42;")
        header.setFixedHeight(70)
        header_layout = QHBoxLayout(header)

        self.status_indicator = StatusIndicator("protected")
        header_layout.addWidget(self.status_indicator)

        header_layout.addStretch()

        self.btn_minimize = QPushButton("─")
        self.btn_minimize.setFixedSize(40, 30)
        self.btn_minimize.setStyleSheet("QPushButton { background: transparent; border: none; color: white; font-size: 18px; } QPushButton:hover { background: #3E3E42; }")
        self.btn_minimize.clicked.connect(self.showMinimized)

        self.btn_maximize = QPushButton("☐")
        self.btn_maximize.setFixedSize(40, 30)
        self.btn_maximize.setStyleSheet("QPushButton { background: transparent; border: none; color: white; font-size: 18px; } QPushButton:hover { background: #3E3E42; }")
        self.btn_maximize.clicked.connect(self.toggle_maximize)

        self.btn_close = QPushButton("✕")
        self.btn_close.setFixedSize(40, 30)
        self.btn_close.setStyleSheet("QPushButton { background: transparent; border: none; color: white; font-size: 14px; } QPushButton:hover { background: #C42B1C; }")
        self.btn_close.clicked.connect(self.close)

        btn_layout = QVBoxLayout()
        btn_layout.addWidget(self.btn_minimize)
        btn_layout.addWidget(self.btn_maximize)
        btn_layout.addWidget(self.btn_close)
        btn_layout.setSpacing(0)
        header_layout.addLayout(btn_layout)

        layout.addWidget(header)

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            self.btn_maximize.setText("☐")
        else:
            self.showMaximized()
            self.btn_maximize.setText("❐")

    def create_tabs(self, layout):
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background: #1E1E1E; }
            QTabBar::tab { background: #2D2D30; color: #AAAAAA; padding: 12px 25px; border: none; font-size: 13px; }
            QTabBar::tab:selected { background: #1E1E1E; color: white; border-top: 2px solid #0078D7; }
            QTabBar::tab:hover { background: #3E3E42; }
        """)

        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_firewall_tab()
        self.create_quarantine_tab()
        self.create_log_tab()
        self.create_settings_tab()

        layout.addWidget(self.tabs)

    def create_dashboard_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("📊 Панель управления")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        stats_group = QFrame()
        stats_group.setStyleSheet("background: #252526; border-radius: 10px; padding: 20px;")
        stats_layout = QHBoxLayout(stats_group)

        self.stat_protection = self.create_stat_card("🛡️", "Защита", "Активна", "#4CAF50")
        self.stat_threats = self.create_stat_card("🦠", "Угроз сегодня", "0", "#F44336")
        self.stat_last_scan = self.create_stat_card("🔍", "Последнее сканирование", "Не проводилось", "#2196F3")
        self.stat_signatures = self.create_stat_card("📝", "База сигнатур", "Загружена", "#9C27B0")

        stats_layout.addWidget(self.stat_protection)
        stats_layout.addWidget(self.stat_threats)
        stats_layout.addWidget(self.stat_last_scan)
        stats_layout.addWidget(self.stat_signatures)
        layout.addWidget(stats_group)

        quick_actions = QLabel("⚡ Быстрые действия")
        quick_actions.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        layout.addWidget(quick_actions)

        actions_layout = QHBoxLayout()
        btn_quick_scan = ModernButton("🚀 Быстрое сканирование")
        btn_quick_scan.clicked.connect(self.quick_scan)
        btn_full_scan = ModernButton("🔍 Полное сканирование")
        btn_full_scan.clicked.connect(self.full_scan)
        btn_update = ModernButton("📥 Обновить базу")
        btn_update.clicked.connect(self.update_signatures)

        actions_layout.addWidget(btn_quick_scan)
        actions_layout.addWidget(btn_full_scan)
        actions_layout.addWidget(btn_update)
        layout.addLayout(actions_layout)

        layout.addStretch()

    def create_stat_card(self, icon, title, value, color):
        card = QFrame()
        card.setStyleSheet(f"background: #2D2D30; border-left: 4px solid {color}; border-radius: 8px; padding: 15px;")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(5)

        icon_label = QLabel(icon)
        icon_label.setStyleSheet("font-size: 28px;")
        card_layout.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")
        card_layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setObjectName("stat_value")
        value_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        card_layout.addWidget(value_label)

        return card

    def create_scan_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("🔍 Сканирование")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        scan_options = QGroupBox("Тип сканирования")
        scan_options.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; } QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; }")
        scan_layout = QHBoxLayout(scan_options)

        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Быстрое сканирование", "Полное сканирование", "Выборочное сканирование"])
        self.scan_type_combo.setStyleSheet("""
            QComboBox {
                background: #3E3E42;
                color: white;
                border: 1px solid #555;
                border-radius: 5px;
                padding: 8px;
                min-width: 200px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow { image: none; border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 8px solid white; }
        """)
        scan_layout.addWidget(self.scan_type_combo)

        btn_select_folder = QPushButton("📁 Выбрать папку")
        btn_select_folder.setStyleSheet("QPushButton { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px 15px; } QPushButton:hover { background: #4E4E52; }")
        btn_select_folder.clicked.connect(self.select_scan_folder)
        scan_layout.addWidget(btn_select_folder)

        self.selected_path_label = QLabel("Не выбрано")
        self.selected_path_label.setStyleSheet("color: #AAAAAA;")
        scan_layout.addWidget(self.selected_path_label)
        scan_layout.addStretch()

        layout.addWidget(scan_options)

        self.scan_progress = QProgressBar()
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                background: #3E3E42;
                border: none;
                border-radius: 5px;
                height: 25px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0078D7, stop:1 #0098FF);
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.scan_progress)

        self.scan_status = QLabel("Готов к сканированию")
        self.scan_status.setStyleSheet("color: #AAAAAA;")
        layout.addWidget(self.scan_progress, 0, Qt.AlignBottom)

        btn_layout = QHBoxLayout()
        self.btn_start_scan = ModernButton("▶ Начать сканирование")
        self.btn_start_scan.clicked.connect(self.start_scan)
        self.btn_pause_scan = ModernButton("⏸ Пауза")
        self.btn_pause_scan.setEnabled(False)
        self.btn_pause_scan.clicked.connect(self.pause_scan)
        self.btn_stop_scan = ModernButton("⏹ Остановить")
        self.btn_stop_scan.setEnabled(False)
        self.btn_stop_scan.clicked.connect(self.stop_scan)

        btn_layout.addWidget(self.btn_start_scan)
        btn_layout.addWidget(self.btn_pause_scan)
        btn_layout.addWidget(self.btn_stop_scan)
        layout.addLayout(btn_layout)

        results_group = QGroupBox("Найденные угрозы")
        results_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; } QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; }")
        results_layout = QVBoxLayout(results_group)

        self.threats_table = QTableWidget()
        self.threats_table.setStyleSheet("""
            QTableWidget {
                background: #1E1E1E;
                color: white;
                border: none;
                gridline-color: #3E3E42;
            }
            QTableWidget::item { padding: 8px; border-bottom: 1px solid #3E3E42; }
            QTableWidget::item:selected { background: #0078D7; }
            QHeaderView::section { background: #2D2D30; color: white; padding: 8px; border: none; }
        """)
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["Файл", "Угроза", "Тип", "Действие"])
        self.threats_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.threats_table)

        layout.addWidget(results_group)

    def select_scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку для сканирования")
        if folder:
            self.selected_path_label.setText(folder)

    def start_scan(self):
        scan_type = self.scan_type_combo.currentIndex()
        paths = []

        if scan_type == 0:
            paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")]
        elif scan_type == 1:
            paths = [os.path.expandvars("%SystemRoot%"), os.path.expanduser("~")]
        else:
            path = self.selected_path_label.text()
            if path and path != "Не выбрано":
                paths = [path]
            else:
                QMessageBox.warning(self, "Внимание", "Выберите папку для сканирования!")
                return

        self.btn_start_scan.setEnabled(False)
        self.btn_pause_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(True)
        self.is_scanning = True

        self.scan_thread = ScanThread(scan_type, paths)
        self.scan_thread.progress_signal.connect(self.update_scan_progress)
        self.scan_thread.threat_found_signal.connect(self.add_threat_found)
        self.scan_thread.finished_signal.connect(self.scan_finished)
        self.scan_thread.start()

    def update_scan_progress(self, count, filepath, status):
        self.scan_progress.setValue(count % 100)
        self.scan_status.setText(f"Сканирование: {os.path.basename(filepath)}")

    def add_threat_found(self, filepath, threat, threat_type):
        self.threats_today += 1
        self.stat_threats.findChild(QLabel, "stat_value").setText(str(self.threats_today))
        self.log_event(f"Обнаружена угроза: {threat} в файле {filepath}")
        row = self.threats_table.rowCount()
        self.threats_table.insertRow(row)
        self.threats_table.setItem(row, 0, QTableWidgetItem(filepath))
        self.threats_table.setItem(row, 1, QTableWidgetItem(threat))
        self.threats_table.setItem(row, 2, QTableWidgetItem("Вирус" if threat_type == 1 else "Подозрительный"))

        btn_quarantine = QPushButton("Карантин")
        btn_quarantine.clicked.connect(lambda: self.move_to_quarantine(filepath, threat))
        self.threats_table.setCellWidget(row, 3, btn_quarantine)

    def move_to_quarantine(self, filepath, threat):
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            filename = os.path.basename(filepath)
            encrypted_name = self.encrypt_filename(filename)
            dest_path = os.path.join(QUARANTINE_DIR, encrypted_name + ".quar")
            shutil.move(filepath, dest_path)

            self.quarantine_items.append({
                "original_path": filepath,
                "quarantine_path": dest_path,
                "threat": threat,
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            self.save_quarantine()
            self.log_event(f"Файл перемещен в карантин: {filepath}")
            QMessageBox.information(self, "Карантин", "Файл успешно перемещен в карантин!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось переместить файл: {e}")

    def encrypt_filename(self, filename):
        key = b"ShieldPro2024"
        encrypted = bytearray(filename.encode())
        for i in range(len(encrypted)):
            encrypted[i] ^= key[i % len(key)]
        return encrypted.hex()[:32]

    def pause_scan(self):
        if self.scan_thread:
            if self.btn_pause_scan.text() == "⏸ Пауза":
                self.scan_thread.pause()
                self.btn_pause_scan.setText("▶ Продолжить")
            else:
                self.scan_thread.resume()
                self.btn_pause_scan.setText("⏸ Пауза")

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()
        self.is_scanning = False
        self.btn_start_scan.setEnabled(True)
        self.btn_pause_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(False)
        self.scan_status.setText("Сканирование остановлено")

    def scan_finished(self, threat_count, results):
        self.is_scanning = False
        self.btn_start_scan.setEnabled(True)
        self.btn_pause_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(False)
        self.scan_progress.setValue(100)
        self.scan_status.setText(f"Сканирование завершено. Найдено угроз: {threat_count}")
        self.stat_last_scan.findChild(QLabel, "stat_value").setText(datetime.datetime.now().strftime("%H:%M %d.%m.%Y"))
        self.log_event(f"Сканирование завершено. Найдено угроз: {threat_count}")

    def quick_scan(self):
        self.tabs.setCurrentIndex(1)
        self.scan_type_combo.setCurrentIndex(0)
        self.start_scan()

    def full_scan(self):
        self.tabs.setCurrentIndex(1)
        self.scan_type_combo.setCurrentIndex(1)
        self.start_scan()

    def update_signatures(self):
        self.log_event("Запуск обновления сигнатур...")
        QMessageBox.information(self, "Обновление", "Проверка обновлений...\n\n(В демо-режиме обновление недоступно)")

    def create_firewall_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("🛡️ Файрвол")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        rule_group = QGroupBox("Добавить правило")
        rule_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; }")
        rule_layout = QHBoxLayout(rule_group)

        rule_layout.addWidget(QLabel("IP:"))
        self.rule_ip = QLineEdit()
        self.rule_ip.setPlaceholderText("0.0.0.0")
        self.rule_ip.setStyleSheet("QLineEdit { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        rule_layout.addWidget(self.rule_ip)

        rule_layout.addWidget(QLabel("Порт:"))
        self.rule_port = QLineEdit()
        self.rule_port.setPlaceholderText("80")
        self.rule_port.setStyleSheet("QLineEdit { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        rule_layout.addWidget(self.rule_port)

        rule_layout.addWidget(QLabel("Направление:"))
        self.rule_direction = QComboBox()
        self.rule_direction.addItems(["Входящие", "Исходящие"])
        self.rule_direction.setStyleSheet("QComboBox { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        rule_layout.addWidget(self.rule_direction)

        rule_layout.addWidget(QLabel("Действие:"))
        self.rule_action = QComboBox()
        self.rule_action.addItems(["Блокировать", "Разрешить"])
        self.rule_action.setStyleSheet("QComboBox { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        rule_layout.addWidget(self.rule_action)

        btn_add_rule = ModernButton("Добавить")
        btn_add_rule.clicked.connect(self.add_firewall_rule)
        rule_layout.addWidget(btn_add_rule)

        layout.addWidget(rule_group)

        rules_table_group = QGroupBox("Активные правила")
        rules_table_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; }")
        rules_layout = QVBoxLayout(rules_table_group)

        self.rules_table = QTableWidget()
        self.rules_table.setStyleSheet("""
            QTableWidget {
                background: #1E1E1E;
                color: white;
                border: none;
                gridline-color: #3E3E42;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section { background: #2D2D30; color: white; padding: 8px; border: none; }
        """)
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels(["ID", "IP", "Порт", "Направление", "Действие"])
        rules_layout.addWidget(self.rules_table)

        btn_clear_rules = QPushButton("Очистить все правила")
        btn_clear_rules.setStyleSheet("QPushButton { background: #C62828; color: white; border: none; border-radius: 5px; padding: 10px; } QPushButton:hover { background: #B71C1C; }")
        btn_clear_rules.clicked.connect(self.clear_firewall_rules)
        rules_layout.addWidget(btn_clear_rules)

        layout.addWidget(rules_table_group)

    def add_firewall_rule(self):
        ip = self.rule_ip.text() or "0.0.0.0"
        try:
            port = int(self.rule_port.text() or "0")
        except:
            port = 0
        direction = self.rule_direction.currentIndex()
        action = self.rule_action.currentIndex()

        if monitor_lib:
            rule_id = monitor_lib.add_firewall_rule(ip.encode(), port, direction, action)
            self.log_event(f"Добавлено правило файрвола: {ip}:{port}")
        else:
            rule_id = len(self.firewall_rules) + 1

        self.firewall_rules.append({"id": rule_id, "ip": ip, "port": port, "direction": direction, "action": action})
        self.update_rules_table()

    def update_rules_table(self):
        self.rules_table.setRowCount(0)
        for rule in self.firewall_rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            self.rules_table.setItem(row, 0, QTableWidgetItem(str(rule["id"])))
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule["ip"]))
            self.rules_table.setItem(row, 2, QTableWidgetItem(str(rule["port"])))
            self.rules_table.setItem(row, 3, QTableWidgetItem("Входящие" if rule["direction"] == 0 else "Исходящие"))
            self.rules_table.setItem(row, 4, QTableWidgetItem("Блокировать" if rule["action"] == 0 else "Разрешить"))

    def clear_firewall_rules(self):
        if monitor_lib:
            monitor_lib.clear_firewall_rules()
        self.firewall_rules.clear()
        self.update_rules_table()
        self.log_event("Все правила файрвола очищены")

    def create_quarantine_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("📛 Карантин")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        info = QLabel("Файлы, помещенные в карантин, не могут причинить вред системе.")
        info.setStyleSheet("color: #AAAAAA;")
        layout.addWidget(info)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setStyleSheet("""
            QTableWidget {
                background: #1E1E1E;
                color: white;
                border: none;
                gridline-color: #3E3E42;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section { background: #2D2D30; color: white; padding: 8px; border: none; }
        """)
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["Исходный путь", "Угроза", "Дата", "Действия"])
        layout.addWidget(self.quarantine_table)

        btns_layout = QHBoxLayout()
        btn_refresh = ModernButton("🔄 Обновить")
        btn_refresh.clicked.connect(self.load_quarantine)
        btn_delete_all = ModernButton("🗑️ Удалить все")
        btn_delete_all.setStyleSheet("QPushButton { background: #C62828; color: white; border: none; border-radius: 6px; padding: 10px 20px; font-weight: bold; } QPushButton:hover { background: #B71C1C; }")
        btn_delete_all.clicked.connect(self.delete_all_quarantine)
        btns_layout.addWidget(btn_refresh)
        btns_layout.addWidget(btn_delete_all)
        layout.addLayout(btns_layout)

    def load_quarantine(self):
        self.quarantine_table.setRowCount(0)
        for item in self.quarantine_items:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(item["original_path"]))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(item["threat"]))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(item["date"]))

            btn_restore = QPushButton("Восстановить")
            btn_restore.clicked.connect(lambda: self.restore_from_quarantine(item))
            btn_delete = QPushButton("Удалить")
            btn_delete.clicked.connect(lambda: self.delete_from_quarantine(item))
            layout = QHBoxLayout()
            layout.addWidget(btn_restore)
            layout.addWidget(btn_delete)
            self.quarantine_table.setCellWidget(row, 3, QWidget())

    def save_quarantine(self):
        with open(os.path.join(DATA_DIR, "quarantine.json"), "w") as f:
            json.dump(self.quarantine_items, f)

    def restore_from_quarantine(self, item):
        try:
            if os.path.exists(item["original_path"]):
                QMessageBox.warning(self, "Внимание", "Файл уже существует на исходном месте!")
                return
            os.rename(item["quarantine_path"], item["original_path"])
            self.quarantine_items.remove(item)
            self.save_quarantine()
            self.load_quarantine()
            self.log_event(f"Восстановлен файл: {item['original_path']}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось восстановить: {e}")

    def delete_from_quarantine(self, item):
        try:
            if os.path.exists(item["quarantine_path"]):
                os.remove(item["quarantine_path"])
            self.quarantine_items.remove(item)
            self.save_quarantine()
            self.load_quarantine()
            self.log_event(f"Удален из карантина: {item['original_path']}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить: {e}")

    def delete_all_quarantine(self):
        reply = QMessageBox.question(self, "Подтверждение", "Вы уверены, что хотите удалить все файлы из карантина?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            for item in self.quarantine_items:
                if os.path.exists(item["quarantine_path"]):
                    os.remove(item["quarantine_path"])
            self.quarantine_items.clear()
            self.save_quarantine()
            self.load_quarantine()
            self.log_event("Очищен карантин")

    def create_log_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("📜 Журнал событий")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        self.log_filter = QComboBox()
        self.log_filter.addItems(["Все события", "Угрозы", "Сканирование", "Файрвол", "Система"])
        self.log_filter.setStyleSheet("QComboBox { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        layout.addWidget(self.log_filter)

        self.log_table = QTableWidget()
        self.log_table.setStyleSheet("""
            QTableWidget {
                background: #1E1E1E;
                color: white;
                border: none;
                gridline-color: #3E3E42;
            }
            QTableWidget::item { padding: 8px; }
            QHeaderView::section { background: #2D2D30; color: white; padding: 8px; border: none; }
        """)
        self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels(["Время", "Тип", "Сообщение"])
        layout.addWidget(self.log_table)

        btn_clear_log = ModernButton("Очистить журнал")
        btn_clear_log.clicked.connect(self.clear_log)
        layout.addWidget(btn_clear_log)

    def log_event(self, message, event_type="info"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_events.append({"time": timestamp, "type": event_type, "message": message})
        self.update_log_display()
        try:
            with open(os.path.join(LOGS_DIR, "shieldpro.log"), "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [{event_type.upper()}] {message}\n")
        except:
            pass

    def update_log_display(self):
        self.log_table.setRowCount(0)
        for event in self.log_events:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            self.log_table.setItem(row, 0, QTableWidgetItem(event["time"]))
            self.log_table.setItem(row, 1, QTableWidgetItem(event["type"]))
            self.log_table.setItem(row, 2, QTableWidgetItem(event["message"]))

    def clear_log(self):
        self.log_events.clear()
        self.update_log_display()
        self.log_event("Журнал очищен")

    def load_log(self):
        log_file = os.path.join(LOGS_DIR, "shieldpro.log")
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if "]" in line:
                            parts = line.split("]", 2)
                            if len(parts) >= 3:
                                time_str = parts[0].strip("[")
                                type_str = parts[1].strip("[ ").strip("]")
                                msg = parts[2].strip()
                                self.log_events.append({"time": time_str, "type": type_str, "message": msg})
            except:
                pass
        if not self.log_events:
            self.log_events = [
                {"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "info", "message": "ShieldPro запущен"},
                {"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": "info", "message": "Загружен модуль сканирования"},
            ]
        self.update_log_display()

    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("⚙️ Настройки")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(title)

        general_group = QGroupBox("Общие")
        general_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; }")
        general_layout = QVBoxLayout(general_group)

        self.chk_autostart = QCheckBox("Запускать при старте системы")
        self.chk_autostart.setStyleSheet("QCheckBox { color: white; }")
        self.chk_autostart.stateChanged.connect(self.toggle_autostart)
        general_layout.addWidget(self.chk_autostart)

        self.chk_realtime = QCheckBox("Защита в реальном времени")
        self.chk_realtime.setStyleSheet("QCheckBox { color: white; }")
        self.chk_realtime.setChecked(True)
        general_layout.addWidget(self.chk_realtime)

        layout.addWidget(general_group)

        update_group = QGroupBox("Обновление")
        update_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; }")
        update_layout = QVBoxLayout(update_group)

        update_layout.addWidget(QLabel("URL обновлений:"))
        self.update_url = QLineEdit("http://localhost/update_signatures.txt")
        self.update_url.setStyleSheet("QLineEdit { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        update_layout.addWidget(self.update_url)

        self.chk_auto_update = QCheckBox("Автоматически проверять обновления")
        self.chk_auto_update.setStyleSheet("QCheckBox { color: white; }")
        self.chk_auto_update.setChecked(True)
        update_layout.addWidget(self.chk_auto_update)

        layout.addWidget(update_group)

        scan_group = QGroupBox("Сканирование")
        scan_group.setStyleSheet("QGroupBox { border: 1px solid #3E3E42; border-radius: 8px; margin-top: 10px; padding: 15px; color: white; }")
        scan_layout = QVBoxLayout(scan_group)

        scan_layout.addWidget(QLabel("Папки для быстрого сканирования:"))
        self.scan_folders = QLineEdit(os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents"))
        self.scan_folders.setStyleSheet("QLineEdit { background: #3E3E42; color: white; border: 1px solid #555; border-radius: 5px; padding: 8px; }")
        scan_layout.addWidget(self.scan_folders)

        layout.addWidget(scan_group)

        layout.addStretch()

    def toggle_autostart(self, state):
        app_path = sys.executable
        if state == Qt.Checked:
            if monitor_lib:
                monitor_lib.register_autostart(app_path.encode(), "ShieldPro".encode())
            self.log_event("Автозапуск включен")
        else:
            if monitor_lib:
                monitor_lib.unregister_autostart("ShieldPro".encode())
            self.log_event("Автозапуск отключен")

    def start_realtime_protection(self):
        if monitor_lib:
            try:
                dirs = [b"C:\\Windows\\System32", os.path.expanduser("~/Downloads").encode()]
                dirs_arr = (ctypes.c_char_p * len(dirs))(*dirs)
                monitor_lib.init_monitor(dirs_arr, len(dirs))
                self.log_event("Защита в реальном времени активирована (native)")
            except Exception as e:
                self.log_event(f"Real-time protection: using simulation mode")
        else:
            self.log_event("Защита в реальном времени (симуляция)")

    def create_status_bar(self, layout):
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("background: #252526; color: #AAAAAA; border-top: 1px solid #3E3E42; padding: 5px;")
        self.status_bar.showMessage("ShieldPro готов к работе")
        layout.addWidget(self.status_bar)

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("ShieldPro - Антивирусная защита")

        tray_menu = QMenu()
        open_action = QAction("Открыть", self)
        open_action.triggered.connect(self.show)
        tray_menu.addAction(open_action)

        protect_action = QAction("Приостановить защиту", self)
        protect_action.triggered.connect(self.toggle_protection)
        protect_action.setObjectName("tray_protect")
        tray_menu.addAction(protect_action)

        tray_menu.addSeparator()

        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_activated)

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()

    def toggle_protection(self):
        self.is_protected = not self.is_protected
        if self.is_protected:
            self.status_indicator.set_status("protected")
            self.status_bar.showMessage("ShieldPro готов к работе")
            self.log_event("Защита возобновлена")
        else:
            self.status_indicator.set_status("disabled")
            self.status_bar.showMessage("Защита приостановлена")
            self.log_event("Защита приостановлена")

    def closeEvent(self, event):
        if self.is_scanning:
            reply = QMessageBox.question(self, "Сканирование", "Сканирование активно. Остановить и выйти?", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.stop_scan()

        if monitor_lib:
            monitor_lib.stop_monitor()

        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#1E1E1E"))
    palette.setColor(QPalette.WindowText, Qt.white)
    app.setPalette(palette)

    window = ShieldProGUI()
    window.show()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()