import sys
import os
import threading
import time
import datetime
import json
import shutil
import hashlib
import platform

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
DATA_DIR = os.path.join(BASE_DIR, "data")
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

for d in [SIGNATURES_DIR, QUARANTINE_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

SIGNATURES_FILE = os.path.join(SIGNATURES_DIR, "signatures.txt")
if not os.path.exists(SIGNATURES_FILE):
    with open(SIGNATURES_FILE, "w") as f:
        f.write("EICAR:58354f2150254041505b345c505a58353428505e\n")
        f.write("TestVirus:48656c6c6f576f726c64\n")

DEFAULT_SETTINGS = {
    "theme": "dark",
    "language": "ru",
    "scan_settings": {
        "max_file_size_mb": 50,
        "scan_depth": 3,
        "scan_exe": True,
        "scan_dll": True,
        "scan_doc": True,
        "scan_archives": True,
        "heuristic_analysis": True,
        "quarantine_threats": True
    },
    "profile": {
        "username": "Пользователь",
        "email": "user@shieldpro.local",
        "protection_level": "Стандартный"
    }
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, ensure_ascii=False, indent=4)
    except:
        pass

settings = load_settings()

TRANSLATIONS = {
    "ru": {
        "title": "ShieldPro - Антивирусная защита",
        "dashboard": "📊 Панель",
        "scan": "🔍 Сканирование",
        "quarantine": "📛 Карантин",
        "log": "📜 Журнал",
        "settings": "⚙️ Настройки",
        "profile": "👤 Профиль",
        "protection_active": "✓ Защита активна",
        "protection_inactive": "✗ Защита отключена",
        "quick_scan": "🚀 Быстрое сканирование",
        "full_scan": "🔍 Полное сканирование",
        "custom_scan": "📁 Выборочное сканирование",
        "update_db": "📥 Обновить базу",
        "signatures": "База сигнатур",
        "entries": "записей",
        "start_scan": "▶ Начать сканирование",
        "stop_scan": "⏹ Стоп",
        "ready": "Готов к сканированию",
        "scanning": "Сканирование...",
        "threats_found": "Найденные угрозы",
        "no_threats": "Угроз не обнаружено",
        "select_folder": "📁 Выбрать папку",
        "folder_not_selected": "Папка не выбрана",
        "quick": "Быстрое",
        "full": "Полное",
        "custom": "Выборочное",
        "quarantine_title": "📛 Карантин",
        "quarantine_empty": "Карантин пуст",
        "refresh": "🔄 Обновить",
        "delete_all": "🗑️ Удалить все",
        "clear_all": "🗑️ Очистить все",
        "log_title": "📜 Журнал событий",
        "clear_log": "Очистить",
        "settings_title": "⚙️ Настройки",
        "scan_settings": "Настройки сканирования",
        "max_file_size": "Макс. размер файла (МБ)",
        "scan_depth": "Глубина сканирования",
        "scan_exe": "Сканировать .exe файлы",
        "scan_dll": "Сканировать .dll файлы",
        "scan_doc": "Сканировать документы",
        "scan_archives": "Сканировать архивы",
        "heuristic": "Эвристический анализ",
        "quarantine_auto": "Авто-карантин",
        "appearance": "Внешний вид",
        "theme": "Тема",
        "dark": "Тёмная",
        "light": "Светлая",
        "language": "Язык",
        "save_settings": "💾 Сохранить настройки",
        "profile_title": "👤 Профиль пользователя",
        "username": "Имя пользователя",
        "email": "Email",
        "protection_level": "Уровень защиты",
        "standard": "Стандартный",
        "enhanced": "Усиленный",
        "maximum": "Максимальный",
        "statistics": "Статистика",
        "total_scans": "Всего сканирований",
        "threats_detected": "Обнаружено угроз",
        "files_quarantined": "Файлов в карантине",
        "last_scan": "Последнее сканирование",
        "scan_complete": "Сканирование завершено",
        "threats_count": "Найдено угроз",
        "never": "Никогда",
        "edit_profile": "✏️ Изменить профиль",
        "profile_saved": "Профиль сохранён",
        "settings_saved": "Настройки сохранены",
        "warning": "Внимание",
        "select_folder_warning": "Выберите папку для сканирования!"
    },
    "en": {
        "title": "ShieldPro - Antivirus Protection",
        "dashboard": "📊 Dashboard",
        "scan": "🔍 Scanning",
        "quarantine": "📛 Quarantine",
        "log": "📜 Log",
        "settings": "⚙️ Settings",
        "profile": "👤 Profile",
        "protection_active": "✓ Protection Active",
        "protection_inactive": "✗ Protection Disabled",
        "quick_scan": "🚀 Quick Scan",
        "full_scan": "🔍 Full Scan",
        "custom_scan": "📁 Custom Scan",
        "update_db": "📥 Update Database",
        "signatures": "Signature database",
        "entries": "entries",
        "start_scan": "▶ Start Scan",
        "stop_scan": "⏹ Stop",
        "ready": "Ready to scan",
        "scanning": "Scanning...",
        "threats_found": "Threats found",
        "no_threats": "No threats detected",
        "select_folder": "📁 Select folder",
        "folder_not_selected": "Folder not selected",
        "quick": "Quick",
        "full": "Full",
        "custom": "Custom",
        "quarantine_title": "📛 Quarantine",
        "quarantine_empty": "Quarantine is empty",
        "refresh": "🔄 Refresh",
        "delete_all": "🗑️ Delete All",
        "clear_all": "🗑️ Clear All",
        "log_title": "📜 Event Log",
        "clear_log": "Clear",
        "settings_title": "⚙️ Settings",
        "scan_settings": "Scan Settings",
        "max_file_size": "Max file size (MB)",
        "scan_depth": "Scan depth",
        "scan_exe": "Scan .exe files",
        "scan_dll": "Scan .dll files",
        "scan_doc": "Scan documents",
        "scan_archives": "Scan archives",
        "heuristic": "Heuristic analysis",
        "quarantine_auto": "Auto-quarantine",
        "appearance": "Appearance",
        "theme": "Theme",
        "dark": "Dark",
        "light": "Light",
        "language": "Language",
        "save_settings": "💾 Save Settings",
        "profile_title": "👤 User Profile",
        "username": "Username",
        "email": "Email",
        "protection_level": "Protection Level",
        "standard": "Standard",
        "enhanced": "Enhanced",
        "maximum": "Maximum",
        "statistics": "Statistics",
        "total_scans": "Total scans",
        "threats_detected": "Threats detected",
        "files_quarantined": "Files in quarantine",
        "last_scan": "Last scan",
        "scan_complete": "Scan complete",
        "threats_count": "Threats found",
        "never": "Never",
        "edit_profile": "✏️ Edit Profile",
        "profile_saved": "Profile saved",
        "settings_saved": "Settings saved",
        "warning": "Warning",
        "select_folder_warning": "Select a folder to scan!"
    }
}

def t(key):
    return TRANSLATIONS.get(settings.get("language", "ru"), TRANSLATIONS["ru"]).get(key, key)

THEMES = {
    "dark": {
        "bg": "#1E1E1E",
        "fg": "white",
        "frame_bg": "#252526",
        "button_bg": "#0078D7",
        "button_fg": "white",
        "danger": "#C62828",
        "success": "#4CAF50",
        "warning": "#FF9800",
        "secondary": "#3E3E42",
        "text_secondary": "#AAAAAA"
    },
    "light": {
        "bg": "#F5F5F5",
        "fg": "#333333",
        "frame_bg": "#FFFFFF",
        "button_bg": "#2196F3",
        "button_fg": "white",
        "danger": "#F44336",
        "success": "#4CAF50",
        "warning": "#FF9800",
        "secondary": "#E0E0E0",
        "text_secondary": "#757575"
    }
}

def get_theme():
    return THEMES.get(settings.get("theme", "dark"), THEMES["dark"])

class PythonScanner:
    def __init__(self):
        self.signatures = {}
        self.load_signatures()
        self.stats = {
            "total_scans": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "last_scan": None
        }
        self.load_stats()

    def load_signatures(self):
        if os.path.exists(SIGNATURES_FILE):
            with open(SIGNATURES_FILE, 'r') as f:
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
        print(f"[ShieldPro] Loaded {len(self.signatures)} signatures")

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

    def load_stats(self):
        stats_file = os.path.join(DATA_DIR, "stats.json")
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    self.stats = json.load(f)
            except:
                pass

    def save_stats(self):
        stats_file = os.path.join(DATA_DIR, "stats.json")
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f)
        except:
            pass

scanner = PythonScanner()

class ShieldProGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(t("title"))
        self.root.geometry("1000x700")
        self.theme = get_theme()
        self.root.configure(bg=self.theme["bg"])
        self.is_scanning = False
        self.threats = []
        self.quarantine_items = []
        self.log_events = []
        self.init_ui()
        self.load_quarantine()
        self.log("ShieldPro started")

    def get_colors(self):
        return self.theme

    def init_ui(self):
        colors = self.get_colors()
        style = {
            "bg": colors["bg"],
            "fg": colors["fg"],
            "selectbackground": colors["button_bg"],
            "font": ("Segoe UI", 10)
        }

        self.notebook = None
        try:
            import tkinter.ttk as ttk
            style = ttk.Style()
            style.theme_use('clam')
            style.configure("TNotebook", background=colors["bg"])
            style.configure("TNotebook.Tab", background=colors["secondary"], foreground=colors["fg"], padding=[10, 5])
            style.map("TNotebook.Tab", background=[("selected", colors["button_bg"])], foreground=[("selected", "white")])

            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
            self.create_tabs_ttk()
        except Exception as e:
            print(f"TTK error: {e}")
            frame = tk.Frame(self.root, bg=colors["bg"])
            frame.pack(fill="both", expand=True, padx=10, pady=10)
            self.status_label = tk.Label(frame, text="ShieldPro GUI", bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 24))
            self.status_label.pack(pady=100)

    def create_tabs_ttk(self):
        self.dashboard_frame = self.create_dashboard()
        self.notebook.add(self.dashboard_frame, text=t("dashboard"))

        self.scan_frame = self.create_scan_tab()
        self.notebook.add(self.scan_frame, text=t("scan"))

        self.quarantine_frame = self.create_quarantine_tab()
        self.notebook.add(self.quarantine_frame, text=t("quarantine"))

        self.log_frame = self.create_log_tab()
        self.notebook.add(self.log_frame, text=t("log"))

        self.settings_frame = self.create_settings_tab()
        self.notebook.add(self.settings_frame, text=t("settings"))

        self.profile_frame = self.create_profile_tab()
        self.notebook.add(self.profile_frame, text=t("profile"))

    def create_dashboard(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])

        tk.Label(frame, text="🛡️ ShieldPro", bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 20, "bold")).pack(pady=20)

        info_frame = tk.Frame(frame, bg=colors["frame_bg"], padx=20, pady=20)
        info_frame.pack(fill="x", padx=20)

        self.status_text = tk.Label(info_frame, text=t("protection_active"), bg=colors["frame_bg"], fg=colors["success"], font=("Segoe UI", 14, "bold"))
        self.status_text.pack()

        tk.Label(info_frame, text="", bg=colors["frame_bg"]).pack()

        btn_frame = tk.Frame(info_frame, bg=colors["frame_bg"])
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text=t("quick_scan"), bg=colors["button_bg"], fg=colors["button_fg"], font=("Segoe UI", 11),
                  command=self.quick_scan, padx=15, pady=8).pack(side="left", padx=5)
        tk.Button(btn_frame, text=t("full_scan"), bg=colors["button_bg"], fg=colors["button_fg"], font=("Segoe UI", 11),
                  command=self.full_scan, padx=15, pady=8).pack(side="left", padx=5)
        tk.Button(btn_frame, text=t("update_db"), bg=colors["success"], fg=colors["button_fg"], font=("Segoe UI", 11),
                  command=self.update_db, padx=15, pady=8).pack(side="left", padx=5)

        tk.Label(frame, text=f"{t('signatures')}: {len(scanner.signatures)} {t('entries')}", bg=colors["bg"], fg=colors["text_secondary"]).pack()

        return frame

    def create_scan_tab(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])
        tk.Label(frame, text=t("scan"), bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)

        opt_frame = tk.Frame(frame, bg=colors["bg"])
        opt_frame.pack(pady=10)

        self.scan_type = tk.StringVar(value="quick")
        tk.Radiobutton(opt_frame, text=t("quick"), variable=self.scan_type, value="quick", bg=colors["bg"], fg=colors["fg"], selectcolor=colors["frame_bg"]).pack(side="left", padx=10)
        tk.Radiobutton(opt_frame, text=t("full"), variable=self.scan_type, value="full", bg=colors["bg"], fg=colors["fg"], selectcolor=colors["frame_bg"]).pack(side="left", padx=10)
        tk.Radiobutton(opt_frame, text=t("custom"), variable=self.scan_type, value="custom", bg=colors["bg"], fg=colors["fg"], selectcolor=colors["frame_bg"]).pack(side="left", padx=10)

        self.custom_path = None
        tk.Button(opt_frame, text=t("select_folder"), bg=colors["secondary"], fg=colors["fg"], command=self.select_folder).pack(side="left", padx=10)

        self.path_label = tk.Label(frame, text=t("folder_not_selected"), bg=colors["bg"], fg=colors["text_secondary"])
        self.path_label.pack()

        btn_frame = tk.Frame(frame, bg=colors["bg"])
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text=t("start_scan"), bg=colors["button_bg"], fg=colors["button_fg"], font=("Segoe UI", 12),
                                   command=self.start_scan, padx=20, pady=10)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(btn_frame, text=t("stop_scan"), bg=colors["danger"], fg=colors["button_fg"], font=("Segoe UI", 12),
                                  command=self.stop_scan, padx=20, pady=10, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.progress = tk.Label(frame, text=t("ready"), bg=colors["bg"], fg=colors["text_secondary"])
        self.progress.pack(pady=5)

        results_frame = tk.Frame(frame, bg=colors["frame_bg"], padx=10, pady=10)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(results_frame, text=t("threats_found") + ":", bg=colors["frame_bg"], fg=colors["fg"]).pack(anchor="w")

        self.threats_list = tk.Listbox(results_frame, bg=colors["bg"], fg=colors["fg"], height=10)
        self.threats_list.pack(fill="both", expand=True)

        return frame

    def create_quarantine_tab(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])
        tk.Label(frame, text=t("quarantine_title"), bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)

        tk.Label(frame, text=t("quarantine_empty").replace("пуст", "isolated files:"), bg=colors["bg"], fg=colors["text_secondary"]).pack()

        self.quarantine_list = tk.Listbox(frame, bg=colors["frame_bg"], fg=colors["fg"], height=20)
        self.quarantine_list.pack(fill="both", expand=True, padx=20, pady=10)

        btn_frame = tk.Frame(frame, bg=colors["bg"])
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text=t("refresh"), bg=colors["secondary"], fg=colors["fg"], command=self.load_quarantine).pack(side="left", padx=5)
        tk.Button(btn_frame, text=t("delete_all"), bg=colors["danger"], fg=colors["button_fg"], command=self.clear_quarantine).pack(side="left", padx=5)

        return frame

    def create_log_tab(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])
        tk.Label(frame, text=t("log_title"), bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)

        self.log_list = tk.Listbox(frame, bg=colors["frame_bg"], fg=colors["fg"], height=25)
        self.log_list.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Button(frame, text=t("clear_log"), bg=colors["secondary"], fg=colors["fg"], command=self.clear_log).pack(pady=5)

        return frame

    def create_settings_tab(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])
        tk.Label(frame, text=t("settings_title"), bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)

        scan_settings = settings.get("scan_settings", DEFAULT_SETTINGS["scan_settings"])

        scan_frame = tk.LabelFrame(frame, text=t("scan_settings"), bg=colors["frame_bg"], fg=colors["fg"], padx=10, pady=10)
        scan_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(scan_frame, text=t("max_file_size"), bg=colors["frame_bg"], fg=colors["fg"]).grid(row=0, column=0, sticky="w", pady=5)
        self.max_file_size_var = tk.IntVar(value=scan_settings.get("max_file_size_mb", 50))
        tk.Entry(scan_frame, textvariable=self.max_file_size_var, width=10).grid(row=0, column=1, padx=10, pady=5)

        tk.Label(scan_frame, text=t("scan_depth"), bg=colors["frame_bg"], fg=colors["fg"]).grid(row=1, column=0, sticky="w", pady=5)
        self.scan_depth_var = tk.IntVar(value=scan_settings.get("scan_depth", 3))
        tk.Entry(scan_frame, textvariable=self.scan_depth_var, width=10).grid(row=1, column=1, padx=10, pady=5)

        self.scan_exe_var = tk.BooleanVar(value=scan_settings.get("scan_exe", True))
        tk.Checkbutton(scan_frame, text=t("scan_exe"), variable=self.scan_exe_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=2, column=0, sticky="w", pady=2)

        self.scan_dll_var = tk.BooleanVar(value=scan_settings.get("scan_dll", True))
        tk.Checkbutton(scan_frame, text=t("scan_dll"), variable=self.scan_dll_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=3, column=0, sticky="w", pady=2)

        self.scan_doc_var = tk.BooleanVar(value=scan_settings.get("scan_doc", True))
        tk.Checkbutton(scan_frame, text=t("scan_doc"), variable=self.scan_doc_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=4, column=0, sticky="w", pady=2)

        self.scan_archives_var = tk.BooleanVar(value=scan_settings.get("scan_archives", True))
        tk.Checkbutton(scan_frame, text=t("scan_archives"), variable=self.scan_archives_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=5, column=0, sticky="w", pady=2)

        self.heuristic_var = tk.BooleanVar(value=scan_settings.get("heuristic_analysis", True))
        tk.Checkbutton(scan_frame, text=t("heuristic"), variable=self.heuristic_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=6, column=0, sticky="w", pady=2)

        self.quarantine_auto_var = tk.BooleanVar(value=scan_settings.get("quarantine_threats", True))
        tk.Checkbutton(scan_frame, text=t("quarantine_auto"), variable=self.quarantine_auto_var, bg=colors["frame_bg"], fg=colors["fg"]).grid(row=7, column=0, sticky="w", pady=2)

        appearance_frame = tk.LabelFrame(frame, text=t("appearance"), bg=colors["frame_bg"], fg=colors["fg"], padx=10, pady=10)
        appearance_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(appearance_frame, text=t("theme"), bg=colors["frame_bg"], fg=colors["fg"]).grid(row=0, column=0, sticky="w", pady=5)
        self.theme_var = tk.StringVar(value=settings.get("theme", "dark"))
        tk.Radiobutton(appearance_frame, text=t("dark"), variable=self.theme_var, value="dark", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=0, column=1, padx=10)
        tk.Radiobutton(appearance_frame, text=t("light"), variable=self.theme_var, value="light", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=0, column=2, padx=10)

        tk.Label(appearance_frame, text=t("language"), bg=colors["frame_bg"], fg=colors["fg"]).grid(row=1, column=0, sticky="w", pady=5)
        self.lang_var = tk.StringVar(value=settings.get("language", "ru"))
        tk.Radiobutton(appearance_frame, text="Русский", variable=self.lang_var, value="ru", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=1, column=1, padx=10)
        tk.Radiobutton(appearance_frame, text="English", variable=self.lang_var, value="en", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=1, column=2, padx=10)

        tk.Button(frame, text=t("save_settings"), bg=colors["success"], fg=colors["button_fg"], font=("Segoe UI", 12),
                  command=self.save_settings, padx=20, pady=10).pack(pady=20)

        return frame

    def create_profile_tab(self):
        colors = self.get_colors()
        frame = tk.Frame(self.root, bg=colors["bg"])
        tk.Label(frame, text=t("profile_title"), bg=colors["bg"], fg=colors["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)

        profile = settings.get("profile", DEFAULT_SETTINGS["profile"])

        info_frame = tk.Frame(frame, bg=colors["frame_bg"], padx=20, pady=20)
        info_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(info_frame, text=t("username") + ":", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=0, column=0, sticky="w", pady=5)
        self.username_var = tk.StringVar(value=profile.get("username", ""))
        tk.Entry(info_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, padx=10, pady=5)

        tk.Label(info_frame, text=t("email") + ":", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=1, column=0, sticky="w", pady=5)
        self.email_var = tk.StringVar(value=profile.get("email", ""))
        tk.Entry(info_frame, textvariable=self.email_var, width=30).grid(row=1, column=1, padx=10, pady=5)

        tk.Label(info_frame, text=t("protection_level") + ":", bg=colors["frame_bg"], fg=colors["fg"]).grid(row=2, column=0, sticky="w", pady=5)
        self.protection_var = tk.StringVar(value=profile.get("protection_level", "Стандартный"))
        protection_combo = tk.Combobox(info_frame, textvariable=self.protection_var, values=[t("standard"), t("enhanced"), t("maximum")], width=28, state="readonly")
        protection_combo.grid(row=2, column=1, padx=10, pady=5)

        tk.Button(frame, text=t("edit_profile"), bg=colors["button_bg"], fg=colors["button_fg"], font=("Segoe UI", 11),
                  command=self.save_profile, padx=15, pady=8).pack(pady=10)

        stats_frame = tk.LabelFrame(frame, text=t("statistics"), bg=colors["frame_bg"], fg=colors["fg"], padx=20, pady=15)
        stats_frame.pack(fill="x", padx=20, pady=10)

        stats = scanner.stats

        tk.Label(stats_frame, text=f"{t('total_scans')}: {stats.get('total_scans', 0)}", bg=colors["frame_bg"], fg=colors["fg"]).pack(anchor="w")
        tk.Label(stats_frame, text=f"{t('threats_detected')}: {stats.get('threats_detected', 0)}", bg=colors["frame_bg"], fg=colors["fg"]).pack(anchor="w")
        tk.Label(stats_frame, text=f"{t('files_quarantined')}: {stats.get('files_quarantined', 0)}", bg=colors["frame_bg"], fg=colors["fg"]).pack(anchor="w")

        last_scan = stats.get("last_scan", None)
        last_scan_str = t("never") if not last_scan else last_scan
        tk.Label(stats_frame, text=f"{t('last_scan')}: {last_scan_str}", bg=colors["frame_bg"], fg=colors["fg"]).pack(anchor="w")

        return frame

    def save_settings(self):
        settings["theme"] = self.theme_var.get()
        settings["language"] = self.lang_var.get()
        settings["scan_settings"] = {
            "max_file_size_mb": self.max_file_size_var.get(),
            "scan_depth": self.scan_depth_var.get(),
            "scan_exe": self.scan_exe_var.get(),
            "scan_dll": self.scan_dll_var.get(),
            "scan_doc": self.scan_doc_var.get(),
            "scan_archives": self.scan_archives_var.get(),
            "heuristic_analysis": self.heuristic_var.get(),
            "quarantine_threats": self.quarantine_auto_var.get()
        }
        save_settings(settings)
        self.log(t("settings_saved"))

        from tkinter import messagebox
        messagebox.showinfo("ShieldPro", t("settings_saved"))

    def save_profile(self):
        profile = settings.get("profile", {})
        profile["username"] = self.username_var.get()
        profile["email"] = self.email_var.get()

        level = self.protection_var.get()
        if level == t("standard"):
            profile["protection_level"] = "Стандартный"
        elif level == t("enhanced"):
            profile["protection_level"] = "Усиленный"
        elif level == t("maximum"):
            profile["protection_level"] = "Максимальный"

        settings["profile"] = profile
        save_settings(settings)
        self.log(t("profile_saved"))

        from tkinter import messagebox
        messagebox.showinfo("ShieldPro", t("profile_saved"))

    def select_folder(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            self.custom_path = folder
            self.path_label.config(text=folder)

    def quick_scan(self):
        self.scan_type.set("quick")
        self.start_scan()

    def full_scan(self):
        self.scan_type.set("full")
        self.start_scan()

    def update_db(self):
        self.log(t("update_db") + "...")
        from tkinter import messagebox
        messagebox.showinfo(t("update_db"), "Checking for updates...\n\n(Demo mode)")

    def start_scan(self):
        if self.is_scanning:
            return

        self.is_scanning = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.threats_list.delete(0, tk.END)
        self.threats = []

        scan_type = self.scan_type.get()
        paths = []

        if scan_type == "quick":
            paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")]
        elif scan_type == "full":
            paths = [os.path.expandvars("%SystemRoot%"), os.path.expanduser("~")]
        elif scan_type == "custom" and self.custom_path:
            paths = [self.custom_path]
        else:
            from tkinter import messagebox
            messagebox.showwarning(t("warning"), t("select_folder_warning"))
            self.is_scanning = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            return

        self.progress.config(text=t("scanning"))
        threading.Thread(target=self.scan_worker, args=(paths,), daemon=True).start()

    def scan_worker(self, paths):
        count = 0
        scan_settings = settings.get("scan_settings", DEFAULT_SETTINGS["scan_settings"])
        max_size = scan_settings.get("max_file_size_mb", 50) * 1024 * 1024
        quarantine = scan_settings.get("quarantine_threats", True)

        for path in paths:
            if not self.is_scanning:
                break
            try:
                if os.path.isfile(path):
                    if os.path.getsize(path) <= max_size:
                        count += 1
                        self.check_file(path, quarantine)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        if not self.is_scanning:
                            break
                        for file in files:
                            if not self.is_scanning:
                                break
                            filepath = os.path.join(root, file)
                            try:
                                if os.path.getsize(filepath) <= max_size:
                                    count += 1
                                    self.check_file(filepath, quarantine)
                                    self.root.after(0, lambda c=count: self.progress.config(text=f"Checked: {c} files"))
                            except:
                                pass
            except:
                pass

        self.root.after(0, self.scan_complete)

    def check_file(self, filepath, quarantine):
        threat = scanner.scan_file(filepath)
        if threat:
            self.threats.append((filepath, threat))
            self.root.after(0, lambda f=filepath, t=threat: self.threats_list.insert(tk.END, f"⚠️ {t}: {f}"))
            self.log(f"Threat detected: {t} in {f}")

            if quarantine:
                self.quarantine_file(filepath, threat)

    def quarantine_file(self, filepath, threat):
        try:
            if not os.path.exists(filepath):
                return

            qdir = QUARANTINE_DIR
            os.makedirs(qdir, exist_ok=True)

            filename = os.path.basename(filepath)
            unique_name = f"{filename}_{int(time.time())}"
            qpath = os.path.join(qdir, unique_name)

            shutil.copy2(filepath, qpath)
            os.remove(filepath)

            self.quarantine_items.append({
                "original_path": filepath,
                "quarantine_path": qpath,
                "threat": threat,
                "date": datetime.datetime.now().isoformat()
            })

            qfile = os.path.join(DATA_DIR, "quarantine.json")
            with open(qfile, 'w') as f:
                json.dump(self.quarantine_items, f)

            scanner.stats["files_quarantined"] = scanner.stats.get("files_quarantined", 0) + 1
            scanner.stats["threats_detected"] = scanner.stats.get("threats_detected", 0) + 1
            scanner.save_stats()

            self.log(f"File quarantined: {filepath}")
        except Exception as e:
            self.log(f"Quarantine error: {str(e)}")

    def scan_complete(self):
        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        count = len(self.threats)
        self.progress.config(text=f"{t('scan_complete')}. {t('threats_count')}: {count}")
        self.log(f"Scan complete. Threats: {count}")

        scanner.stats["total_scans"] = scanner.stats.get("total_scans", 0) + 1
        scanner.stats["last_scan"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        scanner.save_stats()

    def stop_scan(self):
        self.is_scanning = False
        self.progress.config(text="Scan stopped")

    def load_quarantine(self):
        self.quarantine_list.delete(0, tk.END)
        qfile = os.path.join(DATA_DIR, "quarantine.json")
        if os.path.exists(qfile):
            try:
                with open(qfile, 'r') as f:
                    self.quarantine_items = json.load(f)
            except:
                self.quarantine_items = []

        if not self.quarantine_items:
            self.quarantine_list.insert(tk.END, t("quarantine_empty"))
        else:
            for item in self.quarantine_items:
                self.quarantine_list.insert(tk.END, f"{item.get('original_path', 'Unknown')} - {item.get('threat', 'Unknown')}")

    def clear_quarantine(self):
        self.quarantine_items = []
        qfile = os.path.join(DATA_DIR, "quarantine.json")
        if os.path.exists(qfile):
            os.remove(qfile)
        self.load_quarantine()
        self.log("Quarantine cleared")

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_events.append(entry)
        self.log_list.insert(tk.END, entry)
        self.log_list.see(tk.END)

        try:
            with open(os.path.join(LOGS_DIR, "shieldpro.log"), "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except:
            pass

    def clear_log(self):
        self.log_events = []
        self.log_list.delete(0, tk.END)
        self.log("Log cleared")

import tkinter as tk
from tkinter import ttk

if __name__ == "__main__":
    root = tk.Tk()
    app = ShieldProGUI(root)
    root.mainloop()