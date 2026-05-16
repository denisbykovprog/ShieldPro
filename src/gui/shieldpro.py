"""ShieldPro AntiVirus v2.0 - Optimized PyQt6 Edition"""
import sys, os, ctypes, json, shutil, hashlib, platform, datetime, time, threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QLineEdit, QTextEdit,
    QProgressBar, QComboBox, QCheckBox, QGroupBox, QSystemTrayIcon, QMenu, QMessageBox,
    QFileDialog, QHeaderView, QSplitter, QFrame, QStatusBar, QScrollArea, QGridLayout,
    QSizePolicy, QSpinBox, QDoubleSpinBox, QSlider, QStackedWidget, QToolBar, QToolButton,
    QRadioButton, QButtonGroup, QDialog, QDialogButtonBox, QFormLayout)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QAction, QIcon, QFont, QColor, QPainter, QLinearGradient, QCursor, QPalette, QBrush

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SIG_DIR = DATA_DIR / "signatures"
QUAR_DIR = DATA_DIR / "quarantine"
LOG_DIR = DATA_DIR / "logs"
MODULES_DIR = BASE_DIR / "modules"
SETTINGS_FILE = DATA_DIR / "settings.json"
QUAR_FILE = DATA_DIR / "quarantine.json"
SIG_FILE = SIG_DIR / "signatures.txt"
DB_PATH = BASE_DIR / "shieldpro.db"

for d in (SIG_DIR, QUAR_DIR, LOG_DIR): d.mkdir(parents=True, exist_ok=True)

if not SIG_FILE.exists():
    SIG_FILE.write_text("EICAR:58354f2150254041505b345c505a58353428505e\nTestVirus:48656c6c6f576f726c64\n")

# ─── Theme Colors ───
THEMES = {
    "dark": {"bg": "#1E1E1E", "surface": "#252526", "card": "#2D2D30", "border": "#3E3E42",
             "primary": "#0078D7", "primary_hover": "#106EBE", "success": "#4CAF50",
             "danger": "#C62828", "warning": "#FF9800", "text": "#FFFFFF", "text2": "#AAAAAA"},
    "light": {"bg": "#F5F5F5", "surface": "#FFFFFF", "card": "#FAFAFA", "border": "#E0E0E0",
              "primary": "#2196F3", "primary_hover": "#1976D2", "success": "#4CAF50",
              "danger": "#F44336", "warning": "#FF9800", "text": "#333333", "text2": "#757575"},
    "blue": {"bg": "#0D1B2A", "surface": "#1B2838", "card": "#243447", "border": "#37475A",
             "primary": "#00B4D8", "primary_hover": "#0096C7", "success": "#2DC653",
             "danger": "#EF476F", "warning": "#FFD166", "text": "#FFFFFF", "text2": "#8D99AE"}
}

LANG = {
    "ru": {"title": "ShieldPro - Антивирус", "dashboard": "📊 Панель", "scan": "🔍 Сканирование",
           "quarantine": "📛 Карантин", "log": "📜 Журнал", "settings": "⚙️ Настройки",
           "profile": "👤 Профиль", "protection": "🛡️ Защита активна", "quick_scan": "🚀 Быстрое",
           "full_scan": "🔍 Полное", "custom_scan": "📁 Выборочное", "update_db": "📥 Обновить базу",
           "start": "▶ Старт", "stop": "⏹ Стоп", "pause": "⏸ Пауза", "resume": "▶ Продолжить",
           "refresh": "🔄 Обновить", "delete_all": "🗑️ Удалить всё", "clear": "Очистить",
           "save": "💾 Сохранить", "export": "📤 Экспорт", "import": "📥 Импорт",
           "no_threats": "Угроз не найдено", "scan_done": "Сканирование завершено",
           "threats_count": "Найдено угроз", "quarantine_empty": "Карантин пуст",
           "stats": "Статистика", "total_scans": "Всего сканирований", "total_threats": "Обнаружено угроз",
           "quarantined": "В карантине", "last_scan": "Последнее сканирование", "never": "Никогда",
           "scan_history": "История сканирований", "date": "Дата", "type": "Тип",
           "files": "Файлов", "threats": "Угрозы", "duration": "Длительность", "status": "Статус",
           "completed": "Завершено", "stopped": "Остановлено", "running": "Выполняется",
           "general": "Общие", "scan_cfg": "Сканирование", "appearance": "Внешний вид",
           "security": "Безопасность", "performance": "Производительность", "notifications": "Уведомления",
           "autostart": "Автозапуск", "realtime": "Защита в реальном времени",
           "auto_update": "Автообновление", "max_file_size": "Макс. размер (МБ)",
           "scan_depth": "Глубина", "scan_exe": "Сканировать .exe", "scan_dll": "Сканировать .dll",
           "scan_doc": "Сканировать документы", "scan_archives": "Сканировать архивы",
           "heuristic": "Эвристика", "auto_quarantine": "Авто-карантин",
           "theme": "Тема", "language": "Язык", "font_size": "Размер шрифта",
           "dark": "Тёмная", "light": "Светлая", "blue": "Синяя",
           "sound": "Звуковые уведомления", "popup": "Всплывающие уведомления",
           "threads": "Потоки сканирования", "priority": "Приоритет процесса",
           "low": "Низкий", "normal": "Нормальный", "high": "Высокий",
           "exclude_paths": "Исключения (пути)", "exclude_ext": "Исключения (расширения)",
           "backup_settings": "Резервная копия настроек", "restore_settings": "Восстановить настройки",
           "settings_saved": "Настройки сохранены", "profile_saved": "Профиль сохранён",
           "export_success": "Настройки экспортированы", "import_success": "Настройки импортированы",
           "warning": "Внимание", "select_folder": "Выберите папку!", "confirm_clear": "Очистить всё?",
           "username": "Имя", "email": "Email", "level": "Уровень защиты",
           "standard": "Стандартный", "enhanced": "Усиленный", "maximum": "Максимальный",
           "scan_speed": "Скорость сканирования", "files_sec": "файлов/сек",
           "avg_duration": "Среднее время", "system_info": "Системная информация",
           "os": "ОС", "python": "Python", "version": "Версия",
           "memory_scan": "Сканирование памяти", "processes": "Процессы",
           "usb_protection": "USB защита", "firewall": "Файрвол"},
    "en": {"title": "ShieldPro - Antivirus", "dashboard": "📊 Dashboard", "scan": "🔍 Scanning",
           "quarantine": "📛 Quarantine", "log": "📜 Log", "settings": "⚙️ Settings",
           "profile": "👤 Profile", "protection": "🛡️ Protection Active", "quick_scan": "🚀 Quick",
           "full_scan": "🔍 Full", "custom_scan": "📁 Custom", "update_db": "📥 Update DB",
           "start": "▶ Start", "stop": "⏹ Stop", "pause": "⏸ Pause", "resume": "▶ Resume",
           "refresh": "🔄 Refresh", "delete_all": "🗑️ Delete All", "clear": "Clear",
           "save": "💾 Save", "export": "📤 Export", "import": "📥 Import",
           "no_threats": "No threats found", "scan_done": "Scan complete",
           "threats_count": "Threats found", "quarantine_empty": "Quarantine empty",
           "stats": "Statistics", "total_scans": "Total scans", "total_threats": "Threats detected",
           "quarantined": "In quarantine", "last_scan": "Last scan", "never": "Never",
           "scan_history": "Scan History", "date": "Date", "type": "Type",
           "files": "Files", "threats": "Threats", "duration": "Duration", "status": "Status",
           "completed": "Completed", "stopped": "Stopped", "running": "Running",
           "general": "General", "scan_cfg": "Scanning", "appearance": "Appearance",
           "security": "Security", "performance": "Performance", "notifications": "Notifications",
           "autostart": "Autostart", "realtime": "Real-time protection",
           "auto_update": "Auto-update", "max_file_size": "Max file size (MB)",
           "scan_depth": "Depth", "scan_exe": "Scan .exe", "scan_dll": "Scan .dll",
           "scan_doc": "Scan documents", "scan_archives": "Scan archives",
           "heuristic": "Heuristic", "auto_quarantine": "Auto-quarantine",
           "theme": "Theme", "language": "Language", "font_size": "Font size",
           "dark": "Dark", "light": "Light", "blue": "Blue",
           "sound": "Sound notifications", "popup": "Popup notifications",
           "threads": "Scan threads", "priority": "Process priority",
           "low": "Low", "normal": "Normal", "high": "High",
           "exclude_paths": "Excluded paths", "exclude_ext": "Excluded extensions",
           "backup_settings": "Backup settings", "restore_settings": "Restore settings",
           "settings_saved": "Settings saved", "profile_saved": "Profile saved",
           "export_success": "Settings exported", "import_success": "Settings imported",
           "warning": "Warning", "select_folder": "Select a folder!", "confirm_clear": "Clear all?",
           "username": "Name", "email": "Email", "level": "Protection level",
           "standard": "Standard", "enhanced": "Enhanced", "maximum": "Maximum",
           "scan_speed": "Scan speed", "files_sec": "files/sec",
           "avg_duration": "Average time", "system_info": "System Info",
           "os": "OS", "python": "Python", "version": "Version",
           "memory_scan": "Memory scan", "processes": "Processes",
           "usb_protection": "USB protection", "firewall": "Firewall"}
}

def t(k): return LANG.get(cfg.language, LANG["ru"]).get(k, k)

# ─── Settings Dataclass ───
@dataclass
class ScanSettings:
    max_file_size_mb: int = 50
    scan_depth: int = 5
    scan_exe: bool = True
    scan_dll: bool = True
    scan_doc: bool = True
    scan_archives: bool = True
    heuristic: bool = True
    auto_quarantine: bool = True
    threads: int = 4
    priority: str = "normal"
    exclude_paths: str = ""
    exclude_ext: str = "tmp,log,bak"

@dataclass
class ProfileSettings:
    username: str = "User"
    email: str = "user@shieldpro.local"
    level: str = "standard"

@dataclass
class AppConfig:
    theme: str = "dark"
    language: str = "ru"
    font_size: int = 10
    scan: ScanSettings = field(default_factory=ScanSettings)
    profile: ProfileSettings = field(default_factory=ProfileSettings)
    autostart: bool = False
    realtime: bool = True
    auto_update: bool = True
    sound: bool = True
    popup: bool = True
    usb_protection: bool = False
    firewall_enabled: bool = False

    @classmethod
    def load(cls):
        if SETTINGS_FILE.exists():
            try:
                d = json.loads(SETTINGS_FILE.read_text("utf-8"))
                scan = ScanSettings(**d.get("scan", {}))
                profile = ProfileSettings(**d.get("profile", {}))
                return cls(theme=d.get("theme","dark"), language=d.get("language","ru"),
                          font_size=d.get("font_size",10), scan=scan, profile=profile,
                          autostart=d.get("autostart",False), realtime=d.get("realtime",True),
                          auto_update=d.get("auto_update",True), sound=d.get("sound",True),
                          popup=d.get("popup",True), usb_protection=d.get("usb_protection",False),
                          firewall_enabled=d.get("firewall_enabled",False))
            except: pass
        return cls()

    def save(self):
        SETTINGS_FILE.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), "utf-8")

    def export_to(self, path):
        Path(path).write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), "utf-8")

    @classmethod
    def import_from(cls, path):
        d = json.loads(Path(path).read_text("utf-8"))
        return cls(theme=d.get("theme","dark"), language=d.get("language","ru"),
                  font_size=d.get("font_size",10), scan=ScanSettings(**d.get("scan",{})),
                  profile=ProfileSettings(**d.get("profile",{})),
                  autostart=d.get("autostart",False), realtime=d.get("realtime",True),
                  auto_update=d.get("auto_update",True), sound=d.get("sound",True),
                  popup=d.get("popup",True), usb_protection=d.get("usb_protection",False),
                  firewall_enabled=d.get("firewall_enabled",False))

cfg = AppConfig.load()

# ─── Scanner Engine ───
class Scanner:
    __slots__ = ("signatures", "stats")
    def __init__(self):
        self.signatures: dict = {}
        self.stats = {"total_scans": 0, "threats_detected": 0, "files_quarantined": 0, "last_scan": None, "history": []}
        self._load_sigs()
        self._load_stats()

    def _load_sigs(self):
        if SIG_FILE.exists():
            for line in SIG_FILE.read_text().splitlines():
                line = line.strip()
                if line and ':' in line and not line.startswith('#'):
                    try:
                        name, hx = line.split(':', 1)
                        self.signatures[name] = bytes.fromhex(hx)
                    except: pass

    def scan_file(self, fp):
        try:
            with open(fp, 'rb') as f:
                data = f.read(65536)
            for name, sig in self.signatures.items():
                if sig in data: return name
        except: pass
        return None

    def _load_stats(self):
        sf = DATA_DIR / "stats.json"
        if sf.exists():
            try: self.stats.update(json.loads(sf.read_text()))
            except: pass

    def save_stats(self):
        (DATA_DIR / "stats.json").write_text(json.dumps(self.stats))

scanner = Scanner()

# ─── Scan Worker Thread ───
class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    threat = pyqtSignal(str, str)
    done = pyqtSignal(int, int)
    stopped = False

    def __init__(self, paths, max_size):
        super().__init__()
        self.paths, self.max_size = paths, max_size

    def run(self):
        count = threats = 0
        for p in self.paths:
            if self.stopped: break
            try:
                if os.path.isfile(p) and os.path.getsize(p) <= self.max_size:
                    count += 1
                    if scanner.scan_file(p):
                        threats += 1
                        self.threat.emit(p, scanner.scan_file(p))
                elif os.path.isdir(p):
                    for root, _, files in os.walk(p):
                        if self.stopped: break
                        for f in files:
                            if self.stopped: break
                            fp = os.path.join(root, f)
                            try:
                                if os.path.getsize(fp) <= self.max_size:
                                    count += 1
                                    t = scanner.scan_file(fp)
                                    if t:
                                        threats += 1
                                        self.threat.emit(fp, t)
                                    self.progress.emit(count, fp)
                            except: pass
            except: pass
        self.done.emit(count, threats)

    def stop(self): self.stopped = True

# ─── Stylesheet Generator ───
def qss(c):
    return f"""
    QMainWindow, QWidget {{ background: {c["bg"]}; color: {c["text"]}; font-size: {cfg.font_size}px; }}
    QTabWidget::pane {{ border: none; background: {c["bg"]}; }}
    QTabBar::tab {{ background: {c["card"]}; color: {c["text2"]}; padding: 10px 20px; border: none; font-size: {cfg.font_size}px; border-top-left-radius: 6px; border-top-right-radius: 6px; }}
    QTabBar::tab:selected {{ background: {c["surface"]}; color: {c["text"]}; border-top: 2px solid {c["primary"]}; }}
    QTabBar::tab:hover {{ background: {c["border"]}; }}
    QPushButton {{ background: {c["primary"]}; border: none; border-radius: 6px; color: white; padding: 8px 16px; font-weight: bold; font-size: {cfg.font_size}px; }}
    QPushButton:hover {{ background: {c["primary_hover"]}; }}
    QPushButton:disabled {{ background: {c["border"]}; color: {c["text2"]}; }}
    QPushButton.danger {{ background: {c["danger"]}; }}
    QPushButton.danger:hover {{ background: #B71C1C; }}
    QPushButton.success {{ background: {c["success"]}; }}
    QGroupBox {{ border: 1px solid {c["border"]}; border-radius: 8px; margin-top: 8px; padding: 12px; color: {c["text"]}; font-weight: bold; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; }}
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{ background: {c["card"]}; color: {c["text"]}; border: 1px solid {c["border"]}; border-radius: 5px; padding: 6px; font-size: {cfg.font_size}px; }}
    QTableWidget {{ background: {c["surface"]}; color: {c["text"]}; border: none; gridline-color: {c["border"]}; font-size: {cfg.font_size}px; }}
    QTableWidget::item {{ padding: 6px; border-bottom: 1px solid {c["border"]}; }}
    QTableWidget::item:selected {{ background: {c["primary"]}; }}
    QHeaderView::section {{ background: {c["card"]}; color: {c["text"]}; padding: 8px; border: none; font-weight: bold; }}
    QProgressBar {{ background: {c["card"]}; border: none; border-radius: 5px; height: 20px; text-align: center; }}
    QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {c["primary"]}, stop:1 {c["primary_hover"]}); border-radius: 5px; }}
    QScrollBar:vertical {{ background: {c["card"]}; width: 8px; border-radius: 4px; }}
    QScrollBar::handle:vertical {{ background: {c["border"]}; border-radius: 4px; min-height: 20px; }}
    QScrollBar::handle:vertical:hover {{ background: {c["text2"]}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QCheckBox {{ color: {c["text"]}; spacing: 8px; }}
    QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 4px; border: 2px solid {c["border"]}; }}
    QCheckBox::indicator:checked {{ background: {c["primary"]}; border-color: {c["primary"]}; }}
    QLabel {{ color: {c["text"]}; }}
    QTextEdit {{ background: {c["surface"]}; color: {c["text"]}; border: 1px solid {c["border"]}; border-radius: 5px; }}
    QRadioButton {{ color: {c["text"]}; }}
    QRadioButton::indicator {{ width: 16px; height: 16px; border-radius: 8px; border: 2px solid {c["border"]}; }}
    QRadioButton::indicator:checked {{ background: {c["primary"]}; border-color: {c["primary"]}; }}
    QSlider::groove:horizontal {{ background: {c["card"]}; height: 6px; border-radius: 3px; }}
    QSlider::handle:horizontal {{ background: {c["primary"]}; width: 16px; margin: -5px 0; border-radius: 8px; }}
    QSlider::sub-page:horizontal {{ background: {c["primary"]}; border-radius: 3px; }}
    """

# ─── Helper: Card Widget ───
def card(icon, title, value, color, parent=None):
    f = QFrame(parent); f.setStyleSheet(f"background: {THEMES[cfg.theme]['card']}; border-left: 3px solid {color}; border-radius: 8px;")
    lay = QVBoxLayout(f); lay.setSpacing(2)
    lay.addWidget(QLabel(icon), alignment=Qt.AlignmentFlag.AlignCenter)
    tl = QLabel(title); tl.setStyleSheet(f"color: {THEMES[cfg.theme]['text2']}; font-size: {cfg.font_size-1}px;"); lay.addWidget(tl, alignment=Qt.AlignmentFlag.AlignCenter)
    vl = QLabel(str(value)); vl.setStyleSheet(f"color: {THEMES[cfg.theme]['text']}; font-size: {cfg.font_size+4}px; font-weight: bold;"); lay.addWidget(vl, alignment=Qt.AlignmentFlag.AlignCenter)
    return f

# ─── Main Window ───
class ShieldProGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_worker: Optional[ScanWorker] = None
        self.quarantine: list = []
        self.log_events: list = []
        self.scan_history: list = []
        self._load_quarantine()
        self._load_log()
        self._load_history()
        self._init_ui()
        self._load_native()

    def _init_ui(self):
        c = THEMES[cfg.theme]
        self.setWindowTitle(t("title")); self.setMinimumSize(1100, 750)
        self.setStyleSheet(qss(c))
        cw = QWidget(); self.setCentralWidget(cw)
        main = QVBoxLayout(cw); main.setContentsMargins(0,0,0,0); main.setSpacing(0)
        main.addWidget(self._header())
        self.tabs = QTabWidget()
        self._build_tabs()
        main.addWidget(self.tabs)
        sb = QStatusBar(); sb.setStyleSheet(f"background:{c['surface']}; color:{c['text2']}; border-top:1px solid {c['border']};")
        sb.showMessage(f"ShieldPro v2.0 | {t('protection')}"); self.setStatusBar(sb)
        self._tray()

    def _header(self):
        c = THEMES[cfg.theme]
        h = QFrame(); h.setStyleSheet(f"background:{c['surface']}; border-bottom:1px solid {c['border']};"); h.setFixedHeight(60)
        lay = QHBoxLayout(h); lay.setContentsMargins(20,5,10,5)
        lay.addWidget(QLabel("🛡️ ShieldPro"), alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addStretch()
        for txt, slot in [("─", self.showMinimized), ("☐", self._toggle_max), ("✕", self.close)]:
            b = QPushButton(txt); b.setFixedSize(35,28); b.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{c['text']};font-size:14px;}}QPushButton:hover{{background:{c['border']};}}")
            b.clicked.connect(slot); lay.addWidget(b)
        return h

    def _toggle_max(self):
        self.showMaximized() if not self.isMaximized() else self.showNormal()

    def _build_tabs(self):
        self.tabs.addTab(self._tab_dashboard(), t("dashboard"))
        self.tabs.addTab(self._tab_scan(), t("scan"))
        self.tabs.addTab(self._tab_quarantine(), t("quarantine"))
        self.tabs.addTab(self._tab_log(), t("log"))
        self.tabs.addTab(self._tab_settings(), t("settings"))
        self.tabs.addTab(self._tab_profile(), t("profile"))

    # ─── Dashboard ───
    def _tab_dashboard(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25); lay.setSpacing(15)
        lay.addWidget(QLabel("📊 " + t("dashboard").split()[1]), alignment=Qt.AlignmentFlag.AlignCenter)
        cards = QHBoxLayout()
        cards.addWidget(card("🛡️", t("protection").split()[1], "Active", THEMES[cfg.theme]["success"]))
        cards.addWidget(card("🦠", t("total_threats"), scanner.stats["threats_detected"], THEMES[cfg.theme]["danger"]))
        cards.addWidget(card("🔍", t("last_scan"), scanner.stats.get("last_scan", t("never")), THEMES[cfg.theme]["primary"]))
        cards.addWidget(card("📝", t("quarantined"), len(self.quarantine), THEMES[cfg.theme]["warning"]))
        lay.addLayout(cards)
        btns = QHBoxLayout()
        for txt, fn in [(t("quick_scan"), self._quick_scan), (t("full_scan"), self._full_scan), (t("update_db"), self._update_db)]:
            b = QPushButton(txt); b.clicked.connect(fn); btns.addWidget(b)
        lay.addLayout(btns); lay.addStretch()
        return w

    # ─── Scan Tab ───
    def _tab_scan(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25)
        self.scan_type = QComboBox(); self.scan_type.addItems([t("quick_scan"), t("full_scan"), t("custom_scan")])
        self.custom_path = None
        row = QHBoxLayout(); row.addWidget(self.scan_type)
        sel = QPushButton(t("custom_scan")); sel.clicked.connect(self._select_folder); row.addWidget(sel)
        self.path_lbl = QLabel(t("select_folder")); row.addWidget(self.path_lbl); row.addStretch()
        lay.addLayout(row)
        self.progress = QProgressBar(); lay.addWidget(self.progress)
        self.status_lbl = QLabel(t("no_threats")); lay.addWidget(self.status_lbl)
        btn_row = QHBoxLayout()
        self.btn_start = QPushButton(t("start")); self.btn_start.clicked.connect(self._start_scan); btn_row.addWidget(self.btn_start)
        self.btn_pause = QPushButton(t("pause")); self.btn_pause.setEnabled(False); self.btn_pause.clicked.connect(self._pause_scan); btn_row.addWidget(self.btn_pause)
        self.btn_stop = QPushButton(t("stop")); self.btn_stop.setEnabled(False); self.btn_stop.clicked.connect(self._stop_scan); btn_row.addWidget(self.btn_stop)
        lay.addLayout(btn_row)
        self.threats_table = QTableWidget(); self.threats_table.setColumnCount(3)
        self.threats_table.setHorizontalHeaderLabels(["Файл", "Угроза", "Действие"]); self.threats_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.threats_table)
        return w

    def _select_folder(self):
        d = QFileDialog.getExistingDirectory(self, t("custom_scan"))
        if d: self.custom_path = d; self.path_lbl.setText(d)

    def _start_scan(self):
        idx = self.scan_type.currentIndex()
        paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")] if idx == 0 else \
                [os.path.expandvars("%SystemRoot%"), os.path.expanduser("~")] if idx == 1 else \
                [self.custom_path] if self.custom_path else None
        if not paths or not paths[0]:
            QMessageBox.warning(self, t("warning"), t("select_folder")); return
        self.btn_start.setEnabled(False); self.btn_pause.setEnabled(True); self.btn_stop.setEnabled(True)
        self.threats_table.setRowCount(0)
        max_sz = cfg.scan.max_file_size_mb * 1024 * 1024
        self.scan_worker = ScanWorker(paths, max_sz)
        self.scan_worker.progress.connect(lambda c, f: self.status_lbl.setText(f"Scanning: {os.path.basename(f)}"))
        self.scan_worker.threat.connect(self._add_threat)
        self.scan_worker.done.connect(self._scan_done)
        self.scan_worker.start()
        self._add_history(t("quick_scan") if idx==0 else t("full_scan") if idx==1 else t("custom_scan"), "running")

    def _pause_scan(self):
        if self.scan_worker:
            if self.scan_worker.isRunning(): self.scan_worker.wait(); self.btn_pause.setText(t("resume"))
            else: self.scan_worker.start(); self.btn_pause.setText(t("pause"))

    def _stop_scan(self):
        if self.scan_worker: self.scan_worker.stop(); self.scan_worker.wait()
        self._scan_finalize(0)

    def _add_threat(self, fp, threat):
        r = self.threats_table.rowCount(); self.threats_table.insertRow(r)
        self.threats_table.setItem(r, 0, QTableWidgetItem(fp))
        self.threats_table.setItem(r, 1, QTableWidgetItem(threat))
        qb = QPushButton("Карантин"); qb.clicked.connect(lambda: self._quarantine_file(fp, threat))
        self.threats_table.setCellWidget(r, 2, qb)
        if cfg.scan.auto_quarantine: self._quarantine_file(fp, threat)

    def _quarantine_file(self, fp, threat):
        try:
            if not os.path.exists(fp): return
            os.makedirs(QUAR_DIR, exist_ok=True)
            qn = f"{os.path.basename(fp)}_{int(time.time())}"
            qp = QUAR_DIR / qn; shutil.copy2(fp, qp); os.remove(fp)
            self.quarantine.append({"original": fp, "quarantine": str(qp), "threat": threat, "date": datetime.datetime.now().isoformat()})
            self._save_quarantine()
            scanner.stats["files_quarantined"] += 1; scanner.stats["threats_detected"] += 1; scanner.save_stats()
            self._log(f"Quarantined: {threat} - {fp}")
        except Exception as e: self._log(f"Quarantine error: {e}")

    def _scan_done(self, count, threats):
        self._scan_finalize(threats)

    def _scan_finalize(self, threats):
        self.btn_start.setEnabled(True); self.btn_pause.setEnabled(False); self.btn_stop.setEnabled(False)
        self.status_lbl.setText(f"{t('scan_done')}. {t('threats_count')}: {threats}")
        scanner.stats["total_scans"] += 1; scanner.stats["last_scan"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M"); scanner.save_stats()
        self._update_history(status=t("completed") if threats >= 0 else t("stopped"), files_scanned=0, threats_found=threats)
        self._log(f"Scan done. Threats: {threats}")

    def _quick_scan(self): self.tabs.setCurrentIndex(1); self.scan_type.setCurrentIndex(0); self._start_scan()
    def _full_scan(self): self.tabs.setCurrentIndex(1); self.scan_type.setCurrentIndex(1); self._start_scan()
    def _update_db(self): QMessageBox.information(self, t("update_db"), "Demo mode")

    # ─── Quarantine Tab ───
    def _tab_quarantine(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25)
        lay.addWidget(QLabel("📛 " + t("quarantine").split()[1]))
        self.quar_table = QTableWidget(); self.quar_table.setColumnCount(4)
        self.quar_table.setHorizontalHeaderLabels(["Путь", "Угроза", "Дата", "Действия"]); self.quar_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.quar_table)
        btns = QHBoxLayout()
        ref = QPushButton(t("refresh")); ref.clicked.connect(self._refresh_quar); btns.addWidget(ref)
        del_all = QPushButton(t("delete_all")); del_all.setStyleSheet("QPushButton.danger"); del_all.clicked.connect(self._clear_quar); btns.addWidget(del_all)
        lay.addLayout(btns); self._refresh_quar()
        return w

    def _refresh_quar(self):
        self.quar_table.setRowCount(0)
        if not self.quarantine: self.quar_table.insertRow(0); self.quar_table.setItem(0, 0, QTableWidgetItem(t("quarantine_empty"))); return
        for i, item in enumerate(self.quarantine):
            self.quar_table.insertRow(i)
            self.quar_table.setItem(i, 0, QTableWidgetItem(item["original"]))
            self.quar_table.setItem(i, 1, QTableWidgetItem(item["threat"]))
            self.quar_table.setItem(i, 2, QTableWidgetItem(item["date"]))
            rb = QPushButton("Restore"); rb.clicked.connect(lambda _, x=item: self._restore_quar(x))
            db = QPushButton("Delete"); db.clicked.connect(lambda _, x=item: self._delete_quar(x))
            cw = QWidget(); cl = QHBoxLayout(cw); cl.setContentsMargins(0,0,0,0); cl.addWidget(rb); cl.addWidget(db)
            self.quar_table.setCellWidget(i, 3, cw)

    def _restore_quar(self, item):
        try:
            if os.path.exists(item["original"]): QMessageBox.warning(self, t("warning"), "File exists!"); return
            shutil.move(item["quarantine"], item["original"]); self.quarantine.remove(item)
            self._save_quarantine(); self._refresh_quar(); self._log(f"Restored: {item['original']}")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))

    def _delete_quar(self, item):
        try:
            if os.path.exists(item["quarantine"]): os.remove(item["quarantine"])
            self.quarantine.remove(item); self._save_quarantine(); self._refresh_quar(); self._log(f"Deleted: {item['original']}")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))

    def _clear_quar(self):
        if QMessageBox.question(self, t("warning"), t("confirm_clear")) == QMessageBox.StandardButton.Yes:
            for item in self.quarantine:
                try:
                    if os.path.exists(item["quarantine"]): os.remove(item["quarantine"])
                except: pass
            self.quarantine.clear(); self._save_quarantine(); self._refresh_quar(); self._log("Quarantine cleared")

    def _save_quarantine(self): QUAR_FILE.write_text(json.dumps(self.quarantine, ensure_ascii=False, indent=2))
    def _load_quarantine(self):
        if QUAR_FILE.exists():
            try: self.quarantine = json.loads(QUAR_FILE.read_text())
            except: self.quarantine = []

    # ─── Log Tab ───
    def _tab_log(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25)
        lay.addWidget(QLabel("📜 " + t("log").split()[1]))
        self.log_table = QTableWidget(); self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels(["Время", "Тип", "Сообщение"]); self.log_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.log_table)
        clr = QPushButton(t("clear")); clr.clicked.connect(self._clear_log); lay.addWidget(clr)
        self._refresh_log(); return w

    def _log(self, msg, etype="info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_events.append({"time": ts, "type": etype, "msg": msg})
        try: (LOG_DIR / "shieldpro.log").open("a", encoding="utf-8").write(f"[{ts}] {msg}\n")
        except: pass

    def _refresh_log(self):
        self.log_table.setRowCount(0)
        for e in self.log_events:
            r = self.log_table.rowCount(); self.log_table.insertRow(r)
            self.log_table.setItem(r, 0, QTableWidgetItem(e["time"]))
            self.log_table.setItem(r, 1, QTableWidgetItem(e["type"]))
            self.log_table.setItem(r, 2, QTableWidgetItem(e["msg"]))

    def _clear_log(self): self.log_events.clear(); self._refresh_log(); self._log("Log cleared")
    def _load_log(self):
        lf = LOG_DIR / "shieldpro.log"
        if lf.exists():
            for line in lf.read_text(encoding="utf-8").splitlines():
                if line: self.log_events.append({"time": datetime.datetime.now().strftime("%H:%M:%S"), "type": "info", "msg": line})
        if not self.log_events: self._log("ShieldPro started")

    # ─── Settings Tab ───
    def _tab_settings(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(QWidget())
        inner = QWidget(); inner_lay = QVBoxLayout(inner); inner_lay.setSpacing(15)
        s = cfg.scan

        # General
        g = QGroupBox(t("general")); gl = QFormLayout(g)
        self.cb_autostart = QCheckBox(t("autostart")); self.cb_autostart.setChecked(cfg.autostart); gl.addRow(self.cb_autostart)
        self.cb_realtime = QCheckBox(t("realtime")); self.cb_realtime.setChecked(cfg.realtime); gl.addRow(self.cb_realtime)
        self.cb_auto_update = QCheckBox(t("auto_update")); self.cb_auto_update.setChecked(cfg.auto_update); gl.addRow(self.cb_auto_update)
        self.cb_usb = QCheckBox(t("usb_protection")); self.cb_usb.setChecked(cfg.usb_protection); gl.addRow(self.cb_usb)
        self.cb_firewall = QCheckBox(t("firewall")); self.cb_firewall.setChecked(cfg.firewall_enabled); gl.addRow(self.cb_firewall)
        inner_lay.addWidget(g)

        # Scan
        g2 = QGroupBox(t("scan_cfg")); g2l = QFormLayout(g2)
        self.sb_max_size = QSpinBox(); self.sb_max_size.setRange(1, 500); self.sb_max_size.setValue(s.max_file_size_mb); g2l.addRow(t("max_file_size"), self.sb_max_size)
        self.sb_depth = QSpinBox(); self.sb_depth.setRange(1, 20); self.sb_depth.setValue(s.scan_depth); g2l.addRow(t("scan_depth"), self.sb_depth)
        self.sb_threads = QSpinBox(); self.sb_threads.setRange(1, 16); self.sb_threads.setValue(s.threads); g2l.addRow(t("threads"), self.sb_threads)
        self.cb_exe = QCheckBox(t("scan_exe")); self.cb_exe.setChecked(s.scan_exe); g2l.addRow(self.cb_exe)
        self.cb_dll = QCheckBox(t("scan_dll")); self.cb_dll.setChecked(s.scan_dll); g2l.addRow(self.cb_dll)
        self.cb_doc = QCheckBox(t("scan_doc")); self.cb_doc.setChecked(s.scan_doc); g2l.addRow(self.cb_doc)
        self.cb_archives = QCheckBox(t("scan_archives")); self.cb_archives.setChecked(s.scan_archives); g2l.addRow(self.cb_archives)
        self.cb_heuristic = QCheckBox(t("heuristic")); self.cb_heuristic.setChecked(s.heuristic); g2l.addRow(self.cb_heuristic)
        self.cb_autoquar = QCheckBox(t("auto_quarantine")); self.cb_autoquar.setChecked(s.auto_quarantine); g2l.addRow(self.cb_autoquar)
        self.le_exclude_paths = QLineEdit(s.exclude_paths); g2l.addRow(t("exclude_paths"), self.le_exclude_paths)
        self.le_exclude_ext = QLineEdit(s.exclude_ext); g2l.addRow(t("exclude_ext"), self.le_exclude_ext)
        self.cb_priority = QComboBox(); self.cb_priority.addItems([t("low"), t("normal"), t("high")])
        self.cb_priority.setCurrentText({"low": t("low"), "normal": t("normal"), "high": t("high")}.get(s.priority, t("normal"))); g2l.addRow(t("priority"), self.cb_priority)
        inner_lay.addWidget(g2)

        # Appearance
        g3 = QGroupBox(t("appearance")); g3l = QFormLayout(g3)
        self.cb_theme = QComboBox(); self.cb_theme.addItems([t("dark"), t("light"), t("blue")])
        self.cb_theme.setCurrentText({"dark": t("dark"), "light": t("light"), "blue": t("blue")}.get(cfg.theme, t("dark"))); g3l.addRow(t("theme"), self.cb_theme)
        self.cb_lang = QComboBox(); self.cb_lang.addItems(["Русский", "English"]); self.cb_lang.setCurrentIndex(0 if cfg.language == "ru" else 1); g3l.addRow(t("language"), self.cb_lang)
        self.sb_font = QSpinBox(); self.sb_font.setRange(8, 18); self.sb_font.setValue(cfg.font_size); g3l.addRow(t("font_size"), self.sb_font)
        inner_lay.addWidget(g3)

        # Notifications
        g4 = QGroupBox(t("notifications")); g4l = QFormLayout(g4)
        self.cb_sound = QCheckBox(t("sound")); self.cb_sound.setChecked(cfg.sound); g4l.addRow(self.cb_sound)
        self.cb_popup = QCheckBox(t("popup")); self.cb_popup.setChecked(cfg.popup); g4l.addRow(self.cb_popup)
        inner_lay.addWidget(g4)

        # Import/Export
        ie = QHBoxLayout()
        exp_btn = QPushButton(t("export")); exp_btn.clicked.connect(self._export_settings); ie.addWidget(exp_btn)
        imp_btn = QPushButton(t("import")); imp_btn.clicked.connect(self._import_settings); ie.addWidget(imp_btn)
        inner_lay.addLayout(ie)

        save_btn = QPushButton(t("save")); save_btn.setStyleSheet("QPushButton.success"); save_btn.clicked.connect(self._save_settings)
        inner_lay.addWidget(save_btn); inner_lay.addStretch()
        scroll.setWidget(inner); lay.addWidget(scroll)
        return w

    def _save_settings(self):
        theme_map = {t("dark"): "dark", t("light"): "light", t("blue"): "blue"}
        cfg.theme = theme_map.get(self.cb_theme.currentText(), "dark")
        cfg.language = "ru" if self.cb_lang.currentIndex() == 0 else "en"
        cfg.font_size = self.sb_font.value()
        cfg.autostart = self.cb_autostart.isChecked()
        cfg.realtime = self.cb_realtime.isChecked()
        cfg.auto_update = self.cb_auto_update.isChecked()
        cfg.sound = self.cb_sound.isChecked()
        cfg.popup = self.cb_popup.isChecked()
        cfg.usb_protection = self.cb_usb.isChecked()
        cfg.firewall_enabled = self.cb_firewall.isChecked()
        cfg.scan.max_file_size_mb = self.sb_max_size.value()
        cfg.scan.scan_depth = self.sb_depth.value()
        cfg.scan.threads = self.sb_threads.value()
        cfg.scan.scan_exe = self.cb_exe.isChecked()
        cfg.scan.scan_dll = self.cb_dll.isChecked()
        cfg.scan.scan_doc = self.cb_doc.isChecked()
        cfg.scan.scan_archives = self.cb_archives.isChecked()
        cfg.scan.heuristic = self.cb_heuristic.isChecked()
        cfg.scan.auto_quarantine = self.cb_autoquar.isChecked()
        cfg.scan.exclude_paths = self.le_exclude_paths.text()
        cfg.scan.exclude_ext = self.le_exclude_ext.text()
        pri_map = {t("low"): "low", t("normal"): "normal", t("high"): "high"}
        cfg.scan.priority = pri_map.get(self.cb_priority.currentText(), "normal")
        cfg.save()
        self.setStyleSheet(qss(THEMES[cfg.theme]))
        self._log(t("settings_saved"))
        QMessageBox.information(self, t("save"), t("settings_saved"))

    def _export_settings(self):
        fp, _ = QFileDialog.getSaveFileName(self, t("export"), str(DATA_DIR / "settings_backup.json"), "JSON (*.json)")
        if fp: cfg.export_to(fp); self._log(t("export_success")); QMessageBox.information(self, t("export"), t("export_success"))

    def _import_settings(self):
        fp, _ = QFileDialog.getOpenFileName(self, t("import"), str(DATA_DIR), "JSON (*.json)")
        if fp:
            try:
                global cfg
                cfg = AppConfig.import_from(fp)
                cfg.save()
                self._log(t("import_success"))
                QMessageBox.information(self, t("import"), t("import_success"))
                self._apply_settings()
            except Exception as e: QMessageBox.critical(self, "Error", str(e))

    def _apply_settings(self):
        self.setStyleSheet(qss(THEMES[cfg.theme]))

    # ─── Profile Tab ───
    def _tab_profile(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(25,25,25,25)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        inner = QWidget(); inner_lay = QVBoxLayout(inner); inner_lay.setSpacing(15)
        p = cfg.profile

        # Profile info
        g = QGroupBox("👤 " + t("profile").split()[1]); gl = QFormLayout(g)
        self.le_username = QLineEdit(p.username); gl.addRow(t("username"), self.le_username)
        self.le_email = QLineEdit(p.email); gl.addRow(t("email"), self.le_email)
        self.cb_level = QComboBox(); self.cb_level.addItems([t("standard"), t("enhanced"), t("maximum")])
        lvl_map = {"Стандартный": t("standard"), "Усиленный": t("enhanced"), "Максимальный": t("maximum"),
                   "standard": t("standard"), "enhanced": t("enhanced"), "maximum": t("maximum")}
        self.cb_level.setCurrentText(lvl_map.get(p.level, t("standard"))); gl.addRow(t("level"), self.cb_level)
        save_prof = QPushButton("💾 " + t("save")); save_prof.clicked.connect(self._save_profile); gl.addRow(save_prof)
        inner_lay.addWidget(g)

        # Statistics
        g2 = QGroupBox("📊 " + t("stats")); g2l = QFormLayout(g2)
        g2l.addRow(t("total_scans"), QLabel(str(scanner.stats["total_scans"])))
        g2l.addRow(t("total_threats"), QLabel(str(scanner.stats["threats_detected"])))
        g2l.addRow(t("quarantined"), QLabel(str(scanner.stats["files_quarantined"])))
        g2l.addRow(t("last_scan"), QLabel(scanner.stats.get("last_scan", t("never"))))
        avg_dur = 0
        if scanner.stats["history"]:
            durations = [h.get("duration", 0) for h in scanner.stats["history"] if h.get("duration")]
            avg_dur = sum(durations) / len(durations) if durations else 0
        g2l.addRow(t("avg_duration"), QLabel(f"{avg_dur:.1f} сек"))
        inner_lay.addWidget(g2)

        # Scan History Table
        g3 = QGroupBox("📜 " + t("scan_history")); g3lay = QVBoxLayout(g3)
        self.history_table = QTableWidget(); self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([t("date"), t("type"), t("files"), t("threats"), t("status")])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        g3lay.addWidget(self.history_table)
        inner_lay.addWidget(g3)

        # System Info
        g4 = QGroupBox("💻 " + t("system_info")); g4l = QFormLayout(g4)
        g4l.addRow(t("os"), QLabel(f"{platform.system()} {platform.release()}"))
        g4l.addRow(t("python"), QLabel(platform.python_version()))
        g4l.addRow(t("version"), QLabel("2.0.0"))
        g4l.addRow("CPU", QLabel(f"{platform.processor()}"))
        g4l.addRow("Arch", QLabel(platform.machine()))
        g4l.addRow("Node", QLabel(platform.node()))
        inner_lay.addWidget(g4)

        inner_lay.addStretch()
        scroll.setWidget(inner); lay.addWidget(scroll)
        self._refresh_history()
        return w

    def _save_profile(self):
        level_map = {t("standard"): "standard", t("enhanced"): "enhanced", t("maximum"): "maximum",
                     "Стандартный": "standard", "Усиленный": "enhanced", "Максимальный": "maximum"}
        cfg.profile.username = self.le_username.text()
        cfg.profile.email = self.le_email.text()
        cfg.profile.level = level_map.get(self.cb_level.currentText(), "standard")
        cfg.save(); self._log(t("profile_saved"))
        QMessageBox.information(self, t("save"), t("profile_saved"))

    def _add_history(self, scan_type, status="running"):
        entry = {"date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "type": scan_type,
                 "files": 0, "threats": 0, "status": status, "duration": 0}
        scanner.stats["history"].append(entry)
        scanner.save_stats()
        self._refresh_history()

    def _update_history(self, status, files_scanned=0, threats_found=0):
        if scanner.stats["history"]:
            h = scanner.stats["history"][-1]
            h["status"] = status; h["files"] = files_scanned; h["threats"] = threats_found
            h["duration"] = time.time() - h.get("_start", time.time())
            scanner.save_stats()
            self._refresh_history()

    def _refresh_history(self):
        if not hasattr(self, 'history_table'): return
        self.history_table.setRowCount(0)
        for h in reversed(scanner.stats.get("history", [])):
            r = self.history_table.rowCount(); self.history_table.insertRow(r)
            self.history_table.setItem(r, 0, QTableWidgetItem(h.get("date", "")))
            self.history_table.setItem(r, 1, QTableWidgetItem(h.get("type", "")))
            self.history_table.setItem(r, 2, QTableWidgetItem(str(h.get("files", 0))))
            self.history_table.setItem(r, 3, QTableWidgetItem(str(h.get("threats", 0))))
            self.history_table.setItem(r, 4, QTableWidgetItem(h.get("status", "")))

    def _load_history(self):
        if not scanner.stats.get("history"): scanner.stats["history"] = []

    # ─── Native Modules ───
    def _load_native(self):
        for name, lib_name in [("engine", "engine.dll"), ("heuristic", "heuristic.dll"), ("monitor", "monitor.dll"), ("updater", "updater.dll")]:
            p = MODULES_DIR / lib_name
            if p.exists():
                try: ctypes.CDLL(str(p)); self._log(f"Loaded: {name}")
                except: pass

    # ─── Tray ───
    def _tray(self):
        self.tray = QSystemTrayIcon(self); self.tray.setToolTip("ShieldPro")
        menu = QMenu()
        menu.addAction("Open", self.show)
        menu.addAction("Exit", self.close)
        self.tray.setContextMenu(menu); self.tray.show()

    def closeEvent(self, e):
        if self.scan_worker and self.scan_worker.isRunning():
            if QMessageBox.question(self, t("warning"), "Stop scan and exit?") == QMessageBox.StandardButton.Yes:
                self.scan_worker.stop(); self.scan_worker.wait()
            else: e.ignore(); return
        e.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = ShieldProGUI(); w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
