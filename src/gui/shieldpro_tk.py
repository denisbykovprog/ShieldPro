"""ShieldPro AntiVirus v2.0 - Tkinter Fallback Edition (Optimized)"""
import sys, os, threading, time, json, shutil, datetime, hashlib, platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
SIG_DIR, QUAR_DIR, LOG_DIR = (os.path.join(DATA_DIR, d) for d in ("signatures", "quarantine", "logs"))
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
QUAR_FILE = os.path.join(DATA_DIR, "quarantine.json")
SIG_FILE = os.path.join(SIG_DIR, "signatures.txt")

for d in (SIG_DIR, QUAR_DIR, LOG_DIR): os.makedirs(d, exist_ok=True)
if not os.path.exists(SIG_FILE):
    open(SIG_FILE, "w").write("EICAR:58354f2150254041505b345c505a58353428505e\nTestVirus:48656c6c6f576f726c64\n")

THEMES = {
    "dark": {"bg": "#1E1E1E", "fg": "white", "frame_bg": "#252526", "button_bg": "#0078D7",
             "danger": "#C62828", "success": "#4CAF50", "warning": "#FF9800", "secondary": "#3E3E42", "text2": "#AAAAAA"},
    "light": {"bg": "#F5F5F5", "fg": "#333333", "frame_bg": "#FFFFFF", "button_bg": "#2196F3",
              "danger": "#F44336", "success": "#4CAF50", "warning": "#FF9800", "secondary": "#E0E0E0", "text2": "#757575"},
    "blue": {"bg": "#0D1B2A", "fg": "white", "frame_bg": "#1B2838", "button_bg": "#00B4D8",
             "danger": "#EF476F", "success": "#2DC653", "warning": "#FFD166", "secondary": "#37475A", "text2": "#8D99AE"}
}

LANG = {
    "ru": {"title": "ShieldPro - Антивирус", "dashboard": "📊 Панель", "scan": "🔍 Сканирование",
           "quarantine": "📛 Карантин", "log": "📜 Журнал", "settings": "⚙️ Настройки", "profile": "👤 Профиль",
           "protection": "✓ Защита активна", "quick_scan": "🚀 Быстрое", "full_scan": "🔍 Полное",
           "custom_scan": "📁 Выборочное", "update_db": "📥 Обновить базу", "start": "▶ Старт",
           "stop": "⏹ Стоп", "refresh": "🔄 Обновить", "delete_all": "🗑️ Удалить всё",
           "save": "💾 Сохранить", "export": "📤 Экспорт", "import": "📥 Импорт",
           "no_threats": "Угроз не найдено", "scan_done": "Сканирование завершено",
           "threats_count": "Найдено угроз", "quarantine_empty": "Карантин пуст",
           "stats": "Статистика", "total_scans": "Всего сканирований", "total_threats": "Обнаружено угроз",
           "quarantined": "В карантине", "last_scan": "Последнее сканирование", "never": "Никогда",
           "scan_history": "История сканирований", "date": "Дата", "type": "Тип", "files": "Файлов",
           "threats": "Угрозы", "status": "Статус", "completed": "Завершено",
           "general": "Общие", "scan_cfg": "Сканирование", "appearance": "Внешний вид",
           "security": "Безопасность", "performance": "Производительность", "notifications": "Уведомления",
           "autostart": "Автозапуск", "realtime": "Защита в реальном времени", "auto_update": "Автообновление",
           "max_file_size": "Макс. размер (МБ)", "scan_depth": "Глубина", "scan_exe": "Сканировать .exe",
           "scan_dll": "Сканировать .dll", "scan_doc": "Сканировать документы", "scan_archives": "Сканировать архивы",
           "heuristic": "Эвристика", "auto_quarantine": "Авто-карантин", "theme": "Тема", "language": "Язык",
           "font_size": "Размер шрифта", "dark": "Тёмная", "light": "Светлая", "blue": "Синяя",
           "sound": "Звуковые уведомления", "popup": "Всплывающие уведомления", "threads": "Потоки",
           "priority": "Приоритет", "low": "Низкий", "normal": "Нормальный", "high": "Высокий",
           "exclude_paths": "Исключения (пути)", "exclude_ext": "Исключения (расширения)",
           "settings_saved": "Настройки сохранены", "profile_saved": "Профиль сохранён",
           "export_success": "Настройки экспортированы", "import_success": "Настройки импортированы",
           "warning": "Внимание", "select_folder": "Выберите папку!", "confirm_clear": "Очистить всё?",
           "username": "Имя", "email": "Email", "level": "Уровень защиты",
           "standard": "Стандартный", "enhanced": "Усиленный", "maximum": "Максимальный",
           "system_info": "Системная информация", "os": "ОС", "python": "Python", "version": "Версия"},
    "en": {"title": "ShieldPro - Antivirus", "dashboard": "📊 Dashboard", "scan": "🔍 Scanning",
           "quarantine": "📛 Quarantine", "log": "📜 Log", "settings": "⚙️ Settings", "profile": "👤 Profile",
           "protection": "✓ Protection Active", "quick_scan": "🚀 Quick", "full_scan": "🔍 Full",
           "custom_scan": "📁 Custom", "update_db": "📥 Update DB", "start": "▶ Start",
           "stop": "⏹ Stop", "refresh": "🔄 Refresh", "delete_all": "🗑️ Delete All",
           "save": "💾 Save", "export": "📤 Export", "import": "📥 Import",
           "no_threats": "No threats found", "scan_done": "Scan complete",
           "threats_count": "Threats found", "quarantine_empty": "Quarantine empty",
           "stats": "Statistics", "total_scans": "Total scans", "total_threats": "Threats detected",
           "quarantined": "In quarantine", "last_scan": "Last scan", "never": "Never",
           "scan_history": "Scan History", "date": "Date", "type": "Type", "files": "Files",
           "threats": "Threats", "status": "Status", "completed": "Completed",
           "general": "General", "scan_cfg": "Scanning", "appearance": "Appearance",
           "security": "Security", "performance": "Performance", "notifications": "Notifications",
           "autostart": "Autostart", "realtime": "Real-time protection", "auto_update": "Auto-update",
           "max_file_size": "Max file size (MB)", "scan_depth": "Depth", "scan_exe": "Scan .exe",
           "scan_dll": "Scan .dll", "scan_doc": "Scan documents", "scan_archives": "Scan archives",
           "heuristic": "Heuristic", "auto_quarantine": "Auto-quarantine", "theme": "Theme", "language": "Language",
           "font_size": "Font size", "dark": "Dark", "light": "Light", "blue": "Blue",
           "sound": "Sound notifications", "popup": "Popup notifications", "threads": "Threads",
           "priority": "Priority", "low": "Low", "normal": "Normal", "high": "High",
           "exclude_paths": "Excluded paths", "exclude_ext": "Excluded extensions",
           "settings_saved": "Settings saved", "profile_saved": "Profile saved",
           "export_success": "Settings exported", "import_success": "Settings imported",
           "warning": "Warning", "select_folder": "Select a folder!", "confirm_clear": "Clear all?",
           "username": "Name", "email": "Email", "level": "Protection level",
           "standard": "Standard", "enhanced": "Enhanced", "maximum": "Maximum",
           "system_info": "System Info", "os": "OS", "python": "Python", "version": "Version"}
}

def t(k): return LANG.get(cfg.language, LANG["ru"]).get(k, k)

class ScanSettings:
    def __init__(self, d=None):
        d = d or {}
        self.max_file_size_mb = d.get("max_file_size_mb", 50)
        self.scan_depth = d.get("scan_depth", 5)
        self.scan_exe = d.get("scan_exe", True); self.scan_dll = d.get("scan_dll", True)
        self.scan_doc = d.get("scan_doc", True); self.scan_archives = d.get("scan_archives", True)
        self.heuristic = d.get("heuristic", True); self.auto_quarantine = d.get("auto_quarantine", True)
        self.threads = d.get("threads", 4); self.priority = d.get("priority", "normal")
        self.exclude_paths = d.get("exclude_paths", ""); self.exclude_ext = d.get("exclude_ext", "tmp,log,bak")
    def dict(self): return {k: getattr(self, k) for k in self.__dict__}

class ProfileSettings:
    def __init__(self, d=None):
        d = d or {}
        self.username = d.get("username", "User"); self.email = d.get("email", "user@shieldpro.local")
        self.level = d.get("level", "standard")
    def dict(self): return {k: getattr(self, k) for k in self.__dict__}

class AppConfig:
    def __init__(self):
        self.theme = "dark"; self.language = "ru"; self.font_size = 10
        self.scan = ScanSettings(); self.profile = ProfileSettings()
        self.autostart = False; self.realtime = True; self.auto_update = True
        self.sound = True; self.popup = True; self.usb_protection = False; self.firewall_enabled = False
    @classmethod
    def load(cls):
        c = cls()
        if os.path.exists(SETTINGS_FILE):
            try:
                d = json.load(open(SETTINGS_FILE, encoding="utf-8"))
                c.theme = d.get("theme", "dark"); c.language = d.get("language", "ru")
                c.font_size = d.get("font_size", 10); c.scan = ScanSettings(d.get("scan", {}))
                c.profile = ProfileSettings(d.get("profile", {}))
                c.autostart = d.get("autostart", False); c.realtime = d.get("realtime", True)
                c.auto_update = d.get("auto_update", True); c.sound = d.get("sound", True)
                c.popup = d.get("popup", True); c.usb_protection = d.get("usb_protection", False)
                c.firewall_enabled = d.get("firewall_enabled", False)
            except: pass
        return c
    def save(self):
        json.dump({"theme": self.theme, "language": self.language, "font_size": self.font_size,
                   "scan": self.scan.dict(), "profile": self.profile.dict(),
                   "autostart": self.autostart, "realtime": self.realtime, "auto_update": self.auto_update,
                   "sound": self.sound, "popup": self.popup, "usb_protection": self.usb_protection,
                   "firewall_enabled": self.firewall_enabled},
                  open(SETTINGS_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

cfg = AppConfig.load()

class Scanner:
    __slots__ = ("signatures", "stats")
    def __init__(self):
        self.signatures = {}; self.stats = {"total_scans": 0, "threats_detected": 0, "files_quarantined": 0, "last_scan": None, "history": []}
        self._load_sigs(); self._load_stats()
    def _load_sigs(self):
        if os.path.exists(SIG_FILE):
            for line in open(SIG_FILE).read().splitlines():
                line = line.strip()
                if line and ':' in line and not line.startswith('#'):
                    try:
                        n, h = line.split(':', 1); self.signatures[n] = bytes.fromhex(h)
                    except: pass
    def scan_file(self, fp):
        try:
            with open(fp, 'rb') as f: data = f.read(65536)
            for n, s in self.signatures.items():
                if s in data: return n
        except: pass
        return None
    def _load_stats(self):
        sf = os.path.join(DATA_DIR, "stats.json")
        if os.path.exists(sf):
            try: self.stats.update(json.load(open(sf)))
            except: pass
    def save_stats(self):
        json.dump(self.stats, open(os.path.join(DATA_DIR, "stats.json"), "w"))

scanner = Scanner()

class ShieldProGUI:
    def __init__(self, root):
        self.root = root; self.root.title(t("title")); self.root.geometry("1050x720")
        self.theme = THEMES[cfg.theme]; self.is_scanning = False; self.threats = []
        self.quarantine = []; self.log_events = []
        self._load_quar(); self._load_log()
        self._init_ui()

    def _init_ui(self):
        c = self.theme
        self.root.configure(bg=c["bg"])
        style = ttk.Style(); style.theme_use('clam')
        style.configure("TNotebook", background=c["bg"])
        style.configure("TNotebook.Tab", background=c["secondary"], foreground=c["fg"], padding=[12, 6])
        style.map("TNotebook.Tab", background=[("selected", c["button_bg"])], foreground=[("selected", "white")])
        nb = ttk.Notebook(self.root); nb.pack(fill="both", expand=True, padx=8, pady=8)
        for frame, label in [(self._dashboard(), t("dashboard")), (self._scan_tab(), t("scan")),
                             (self._quar_tab(), t("quarantine")), (self._log_tab(), t("log")),
                             (self._settings_tab(), t("settings")), (self._profile_tab(), t("profile"))]:
            nb.add(frame, text=label)

    def _btn(self, parent, text, cmd, bg=None, fg="white", **kw):
        return tk.Button(parent, text=text, bg=bg or self.theme["button_bg"], fg=fg, font=("Segoe UI", 10, "bold"), command=cmd, **kw)

    def _dashboard(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        tk.Label(f, text="🛡️ ShieldPro", bg=c["bg"], fg=c["fg"], font=("Segoe UI", 22, "bold")).pack(pady=20)
        info = tk.Frame(f, bg=c["frame_bg"], padx=20, pady=15); info.pack(fill="x", padx=20)
        tk.Label(info, text=t("protection"), bg=c["frame_bg"], fg=c["success"], font=("Segoe UI", 14, "bold")).pack()
        bf = tk.Frame(info, bg=c["frame_bg"]); bf.pack(pady=10)
        self._btn(bf, t("quick_scan"), self._quick_scan).pack(side="left", padx=5)
        self._btn(bf, t("full_scan"), self._full_scan).pack(side="left", padx=5)
        self._btn(bf, t("update_db"), self._update_db, bg=c["success"]).pack(side="left", padx=5)
        tk.Label(f, text=f"{t('total_threats')}: {scanner.stats['threats_detected']}", bg=c["bg"], fg=c["text2"]).pack(pady=5)
        return f

    def _scan_tab(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        tk.Label(f, text=t("scan"), bg=c["bg"], fg=c["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)
        of = tk.Frame(f, bg=c["bg"]); of.pack(pady=5)
        self.scan_type = tk.StringVar(value="quick")
        for txt, val in [(t("quick_scan"), "quick"), (t("full_scan"), "full"), (t("custom_scan"), "custom")]:
            tk.Radiobutton(of, text=txt, variable=self.scan_type, value=val, bg=c["bg"], fg=c["fg"]).pack(side="left", padx=8)
        self.custom_path = None
        self._btn(of, t("custom_scan"), self._select_folder, bg=c["secondary"]).pack(side="left", padx=5)
        self.path_lbl = tk.Label(f, text="", bg=c["bg"], fg=c["text2"]); self.path_lbl.pack()
        bf = tk.Frame(f, bg=c["bg"]); bf.pack(pady=8)
        self.start_btn = self._btn(bf, t("start"), self._start_scan); self.start_btn.pack(side="left", padx=5)
        self.stop_btn = self._btn(bf, t("stop"), self._stop_scan, bg=c["danger"], state="disabled"); self.stop_btn.pack(side="left", padx=5)
        self.progress = tk.Label(f, text=t("no_threats"), bg=c["bg"], fg=c["text2"]); self.progress.pack(pady=5)
        rf = tk.Frame(f, bg=c["frame_bg"], padx=10, pady=10); rf.pack(fill="both", expand=True, padx=15, pady=10)
        self.threats_list = tk.Listbox(rf, bg=c["bg"], fg=c["fg"], height=12); self.threats_list.pack(fill="both", expand=True)
        return f

    def _select_folder(self):
        d = filedialog.askdirectory()
        if d: self.custom_path = d; self.path_lbl.config(text=d)

    def _start_scan(self):
        if self.is_scanning: return
        st = self.scan_type.get()
        paths = [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")] if st == "quick" else \
                [os.path.expandvars("%SystemRoot%"), os.path.expanduser("~")] if st == "full" else \
                [self.custom_path] if self.custom_path else None
        if not paths or not paths[0]:
            messagebox.showwarning(t("warning"), t("select_folder")); return
        self.is_scanning = True; self.start_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        self.threats_list.delete(0, tk.END); self.threats = []
        max_sz = cfg.scan.max_file_size_mb * 1024 * 1024
        threading.Thread(target=self._scan_worker, args=(paths, max_sz), daemon=True).start()

    def _scan_worker(self, paths, max_sz):
        count = 0
        for p in paths:
            if not self.is_scanning: break
            try:
                if os.path.isfile(p) and os.path.getsize(p) <= max_sz:
                    count += 1; self._check_file(p)
                elif os.path.isdir(p):
                    for root, _, files in os.walk(p):
                        if not self.is_scanning: break
                        for fn in files:
                            if not self.is_scanning: break
                            fp = os.path.join(root, fn)
                            try:
                                if os.path.getsize(fp) <= max_sz:
                                    count += 1; self._check_file(fp)
                                    self.root.after(0, lambda c=count: self.progress.config(text=f"Checked: {c}"))
                            except: pass
            except: pass
        self.root.after(0, lambda: self._scan_done(count))

    def _check_file(self, fp):
        threat = scanner.scan_file(fp)
        if threat:
            self.threats.append((fp, threat))
            self.root.after(0, lambda f=fp, t=threat: self.threats_list.insert(tk.END, f"⚠ {t}: {f}"))
            if cfg.scan.auto_quarantine: self._quarantine_file(fp, threat)

    def _quarantine_file(self, fp, threat):
        try:
            if not os.path.exists(fp): return
            os.makedirs(QUAR_DIR, exist_ok=True)
            qn = f"{os.path.basename(fp)}_{int(time.time())}"; qp = os.path.join(QUAR_DIR, qn)
            shutil.copy2(fp, qp); os.remove(fp)
            self.quarantine.append({"original": fp, "quarantine": qp, "threat": threat, "date": datetime.datetime.now().isoformat()})
            self._save_quar()
            scanner.stats["files_quarantined"] += 1; scanner.stats["threats_detected"] += 1; scanner.save_stats()
        except: pass

    def _scan_done(self, count):
        self.is_scanning = False; self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled")
        self.progress.config(text=f"{t('scan_done')}. {t('threats_count')}: {len(self.threats)}")
        scanner.stats["total_scans"] += 1; scanner.stats["last_scan"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M"); scanner.save_stats()
        self._log(f"Scan done. Threats: {len(self.threats)}")

    def _stop_scan(self): self.is_scanning = False
    def _quick_scan(self): self.scan_type.set("quick"); self._start_scan()
    def _full_scan(self): self.scan_type.set("full"); self._start_scan()
    def _update_db(self): messagebox.showinfo(t("update_db"), "Demo mode")

    def _quar_tab(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        tk.Label(f, text=t("quarantine"), bg=c["bg"], fg=c["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)
        self.quar_list = tk.Listbox(f, bg=c["frame_bg"], fg=c["fg"], height=18); self.quar_list.pack(fill="both", expand=True, padx=15, pady=5)
        bf = tk.Frame(f, bg=c["bg"]); bf.pack(pady=8)
        self._btn(bf, t("refresh"), self._refresh_quar, bg=c["secondary"]).pack(side="left", padx=5)
        self._btn(bf, t("delete_all"), self._clear_quar, bg=c["danger"]).pack(side="left", padx=5)
        self._refresh_quar(); return f

    def _refresh_quar(self):
        self.quar_list.delete(0, tk.END)
        if not self.quarantine: self.quar_list.insert(tk.END, t("quarantine_empty"))
        else:
            for item in self.quarantine:
                self.quar_list.insert(tk.END, f"{item['original']} - {item['threat']}")

    def _clear_quar(self):
        if messagebox.askyesno(t("warning"), t("confirm_clear")):
            for item in self.quarantine:
                try:
                    if os.path.exists(item["quarantine"]): os.remove(item["quarantine"])
                except: pass
            self.quarantine.clear(); self._save_quar(); self._refresh_quar()

    def _save_quar(self): json.dump(self.quarantine, open(QUAR_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    def _load_quar(self):
        if os.path.exists(QUAR_FILE):
            try: self.quarantine = json.load(open(QUAR_FILE, encoding="utf-8"))
            except: self.quarantine = []

    def _log_tab(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        tk.Label(f, text=t("log"), bg=c["bg"], fg=c["fg"], font=("Segoe UI", 16, "bold")).pack(pady=10)
        self.log_list = tk.Listbox(f, bg=c["frame_bg"], fg=c["fg"], height=22); self.log_list.pack(fill="both", expand=True, padx=15, pady=5)
        self._btn(f, "Очистить", self._clear_log, bg=c["secondary"]).pack(pady=5)
        self._refresh_log(); return f

    def _log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S"); entry = f"[{ts}] {msg}"
        self.log_events.append(entry)
        try: self.log_list.insert(tk.END, entry); self.log_list.see(tk.END)
        except: pass
        try: open(os.path.join(LOG_DIR, "shieldpro.log"), "a", encoding="utf-8").write(entry + "\n")
        except: pass

    def _refresh_log(self):
        for e in self.log_events: self.log_list.insert(tk.END, e)
    def _clear_log(self): self.log_events.clear(); self.log_list.delete(0, tk.END); self._log("Log cleared")
    def _load_log(self):
        lf = os.path.join(LOG_DIR, "shieldpro.log")
        if os.path.exists(lf):
            for line in open(lf, encoding="utf-8").read().splitlines():
                if line: self.log_events.append(line)
        if not self.log_events: self._log("ShieldPro started")

    def _settings_tab(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        cv = tk.Canvas(f, bg=c["bg"]); cv.pack(side="left", fill="both", expand=True)
        sb = tk.Scrollbar(f, orient="vertical", command=cv.yview); sb.pack(side="right", fill="y")
        cv.configure(yscrollcommand=sb.set)
        inner = tk.Frame(cv, bg=c["bg"]); cv.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))

        # General
        gf = tk.LabelFrame(inner, text=t("general"), bg=c["frame_bg"], fg=c["fg"], padx=10, pady=8)
        gf.pack(fill="x", padx=15, pady=5)
        self.v_autostart = tk.BooleanVar(value=cfg.autostart); tk.Checkbutton(gf, text=t("autostart"), variable=self.v_autostart, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")
        self.v_realtime = tk.BooleanVar(value=cfg.realtime); tk.Checkbutton(gf, text=t("realtime"), variable=self.v_realtime, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")
        self.v_auto_update = tk.BooleanVar(value=cfg.auto_update); tk.Checkbutton(gf, text=t("auto_update"), variable=self.v_auto_update, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")
        self.v_usb = tk.BooleanVar(value=cfg.usb_protection); tk.Checkbutton(gf, text="USB " + t("security"), variable=self.v_usb, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")
        self.v_firewall = tk.BooleanVar(value=cfg.firewall_enabled); tk.Checkbutton(gf, text=t("firewall") if "firewall" in LANG[cfg.language] else "Firewall", variable=self.v_firewall, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")

        # Scan
        sf2 = tk.LabelFrame(inner, text=t("scan_cfg"), bg=c["frame_bg"], fg=c["fg"], padx=10, pady=8)
        sf2.pack(fill="x", padx=15, pady=5)
        tk.Label(sf2, text=t("max_file_size"), bg=c["frame_bg"], fg=c["fg"]).grid(row=0, column=0, sticky="w", pady=3)
        self.v_max_sz = tk.IntVar(value=cfg.scan.max_file_size_mb); tk.Entry(sf2, textvariable=self.v_max_sz, width=8).grid(row=0, column=1, padx=5)
        tk.Label(sf2, text=t("scan_depth"), bg=c["frame_bg"], fg=c["fg"]).grid(row=1, column=0, sticky="w", pady=3)
        self.v_depth = tk.IntVar(value=cfg.scan.scan_depth); tk.Entry(sf2, textvariable=self.v_depth, width=8).grid(row=1, column=1, padx=5)
        tk.Label(sf2, text=t("threads"), bg=c["frame_bg"], fg=c["fg"]).grid(row=2, column=0, sticky="w", pady=3)
        self.v_threads = tk.IntVar(value=cfg.scan.threads); tk.Entry(sf2, textvariable=self.v_threads, width=8).grid(row=2, column=1, padx=5)
        self.v_exe = tk.BooleanVar(value=cfg.scan.scan_exe); tk.Checkbutton(sf2, text=t("scan_exe"), variable=self.v_exe, bg=c["frame_bg"], fg=c["fg"]).grid(row=3, column=0, sticky="w")
        self.v_dll = tk.BooleanVar(value=cfg.scan.scan_dll); tk.Checkbutton(sf2, text=t("scan_dll"), variable=self.v_dll, bg=c["frame_bg"], fg=c["fg"]).grid(row=4, column=0, sticky="w")
        self.v_doc = tk.BooleanVar(value=cfg.scan.scan_doc); tk.Checkbutton(sf2, text=t("scan_doc"), variable=self.v_doc, bg=c["frame_bg"], fg=c["fg"]).grid(row=5, column=0, sticky="w")
        self.v_archives = tk.BooleanVar(value=cfg.scan.scan_archives); tk.Checkbutton(sf2, text=t("scan_archives"), variable=self.v_archives, bg=c["frame_bg"], fg=c["fg"]).grid(row=6, column=0, sticky="w")
        self.v_heuristic = tk.BooleanVar(value=cfg.scan.heuristic); tk.Checkbutton(sf2, text=t("heuristic"), variable=self.v_heuristic, bg=c["frame_bg"], fg=c["fg"]).grid(row=7, column=0, sticky="w")
        self.v_autoquar = tk.BooleanVar(value=cfg.scan.auto_quarantine); tk.Checkbutton(sf2, text=t("auto_quarantine"), variable=self.v_autoquar, bg=c["frame_bg"], fg=c["fg"]).grid(row=8, column=0, sticky="w")
        tk.Label(sf2, text=t("exclude_paths"), bg=c["frame_bg"], fg=c["fg"]).grid(row=9, column=0, sticky="w", pady=3)
        self.v_excl_paths = tk.StringVar(value=cfg.scan.exclude_paths); tk.Entry(sf2, textvariable=self.v_excl_paths, width=30).grid(row=9, column=1, padx=5)
        tk.Label(sf2, text=t("exclude_ext"), bg=c["frame_bg"], fg=c["fg"]).grid(row=10, column=0, sticky="w", pady=3)
        self.v_excl_ext = tk.StringVar(value=cfg.scan.exclude_ext); tk.Entry(sf2, textvariable=self.v_excl_ext, width=30).grid(row=10, column=1, padx=5)

        # Appearance
        af = tk.LabelFrame(inner, text=t("appearance"), bg=c["frame_bg"], fg=c["fg"], padx=10, pady=8)
        af.pack(fill="x", padx=15, pady=5)
        tk.Label(af, text=t("theme"), bg=c["frame_bg"], fg=c["fg"]).grid(row=0, column=0, sticky="w", pady=3)
        self.v_theme = tk.StringVar(value=cfg.theme)
        for txt, val in [(t("dark"), "dark"), (t("light"), "light"), (t("blue"), "blue")]:
            tk.Radiobutton(af, text=txt, variable=self.v_theme, value=val, bg=c["frame_bg"], fg=c["fg"]).grid(row=0, column={"dark":1,"light":2,"blue":3}[val], padx=5)
        tk.Label(af, text=t("language"), bg=c["frame_bg"], fg=c["fg"]).grid(row=1, column=0, sticky="w", pady=3)
        self.v_lang = tk.StringVar(value=cfg.language)
        tk.Radiobutton(af, text="Русский", variable=self.v_lang, value="ru", bg=c["frame_bg"], fg=c["fg"]).grid(row=1, column=1, padx=10)
        tk.Radiobutton(af, text="English", variable=self.v_lang, value="en", bg=c["frame_bg"], fg=c["fg"]).grid(row=1, column=2, padx=10)

        # Notifications
        nf = tk.LabelFrame(inner, text=t("notifications"), bg=c["frame_bg"], fg=c["fg"], padx=10, pady=8)
        nf.pack(fill="x", padx=15, pady=5)
        self.v_sound = tk.BooleanVar(value=cfg.sound); tk.Checkbutton(nf, text=t("sound"), variable=self.v_sound, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")
        self.v_popup = tk.BooleanVar(value=cfg.popup); tk.Checkbutton(nf, text=t("popup"), variable=self.v_popup, bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w")

        # Import/Export
        ief = tk.Frame(inner, bg=c["bg"]); ief.pack(pady=10)
        self._btn(ief, t("export"), self._export_settings, bg=c["secondary"]).pack(side="left", padx=5)
        self._btn(ief, t("import"), self._import_settings, bg=c["secondary"]).pack(side="left", padx=5)

        self._btn(inner, t("save"), self._save_settings, bg=c["success"], padx=20, pady=8).pack(pady=10)
        return f

    def _save_settings(self):
        cfg.theme = self.v_theme.get(); cfg.language = self.v_lang.get()
        cfg.autostart = self.v_autostart.get(); cfg.realtime = self.v_realtime.get()
        cfg.auto_update = self.v_auto_update.get(); cfg.sound = self.v_sound.get()
        cfg.popup = self.v_popup.get(); cfg.usb_protection = self.v_usb.get()
        cfg.firewall_enabled = self.v_firewall.get()
        cfg.scan.max_file_size_mb = self.v_max_sz.get(); cfg.scan.scan_depth = self.v_depth.get()
        cfg.scan.threads = self.v_threads.get()
        cfg.scan.scan_exe = self.v_exe.get(); cfg.scan.scan_dll = self.v_dll.get()
        cfg.scan.scan_doc = self.v_doc.get(); cfg.scan.scan_archives = self.v_archives.get()
        cfg.scan.heuristic = self.v_heuristic.get(); cfg.scan.auto_quarantine = self.v_autoquar.get()
        cfg.scan.exclude_paths = self.v_excl_paths.get(); cfg.scan.exclude_ext = self.v_excl_ext.get()
        cfg.save(); self._log(t("settings_saved")); messagebox.showinfo(t("save"), t("settings_saved"))

    def _export_settings(self):
        fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if fp:
            json.dump({"theme": cfg.theme, "language": cfg.language, "font_size": cfg.font_size,
                       "scan": cfg.scan.dict(), "profile": cfg.profile.dict(),
                       "autostart": cfg.autostart, "realtime": cfg.realtime, "auto_update": cfg.auto_update,
                       "sound": cfg.sound, "popup": cfg.popup, "usb_protection": cfg.usb_protection,
                       "firewall_enabled": cfg.firewall_enabled},
                      open(fp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
            self._log(t("export_success")); messagebox.showinfo(t("export"), t("export_success"))

    def _import_settings(self):
        fp = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if fp:
            try:
                d = json.load(open(fp, encoding="utf-8"))
                cfg.theme = d.get("theme", "dark"); cfg.language = d.get("language", "ru")
                cfg.font_size = d.get("font_size", 10); cfg.scan = ScanSettings(d.get("scan", {}))
                cfg.profile = ProfileSettings(d.get("profile", {}))
                cfg.autostart = d.get("autostart", False); cfg.realtime = d.get("realtime", True)
                cfg.auto_update = d.get("auto_update", True); cfg.sound = d.get("sound", True)
                cfg.popup = d.get("popup", True); cfg.usb_protection = d.get("usb_protection", False)
                cfg.firewall_enabled = d.get("firewall_enabled", False)
                cfg.save(); self._log(t("import_success")); messagebox.showinfo(t("import"), t("import_success"))
            except Exception as e: messagebox.showerror("Error", str(e))

    def _profile_tab(self):
        c = self.theme; f = tk.Frame(self.root, bg=c["bg"])
        pf = tk.LabelFrame(f, text="👤 " + t("profile").split()[1], bg=c["frame_bg"], fg=c["fg"], padx=15, pady=10)
        pf.pack(fill="x", padx=15, pady=8)
        tk.Label(pf, text=t("username"), bg=c["frame_bg"], fg=c["fg"]).grid(row=0, column=0, sticky="w", pady=5)
        self.v_username = tk.StringVar(value=cfg.profile.username); tk.Entry(pf, textvariable=self.v_username, width=30).grid(row=0, column=1, padx=10)
        tk.Label(pf, text=t("email"), bg=c["frame_bg"], fg=c["fg"]).grid(row=1, column=0, sticky="w", pady=5)
        self.v_email = tk.StringVar(value=cfg.profile.email); tk.Entry(pf, textvariable=self.v_email, width=30).grid(row=1, column=1, padx=10)
        tk.Label(pf, text=t("level"), bg=c["frame_bg"], fg=c["fg"]).grid(row=2, column=0, sticky="w", pady=5)
        self.v_level = tk.StringVar(value=cfg.profile.level)
        ttk.Combobox(pf, textvariable=self.v_level, values=["standard", "enhanced", "maximum"], width=28, state="readonly").grid(row=2, column=1, padx=10)
        self._btn(pf, t("save"), self._save_profile, bg=c["button_bg"]).grid(row=3, column=1, pady=10)

        sf = tk.LabelFrame(f, text="📊 " + t("stats"), bg=c["frame_bg"], fg=c["fg"], padx=15, pady=10)
        sf.pack(fill="x", padx=15, pady=8)
        for lbl, val in [(t("total_scans"), scanner.stats["total_scans"]), (t("total_threats"), scanner.stats["threats_detected"]),
                         (t("quarantined"), scanner.stats["files_quarantined"]), (t("last_scan"), scanner.stats.get("last_scan", t("never")))]:
            tk.Label(sf, text=f"{lbl}: {val}", bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w", pady=2)

        hf = tk.LabelFrame(f, text="📜 " + t("scan_history"), bg=c["frame_bg"], fg=c["fg"], padx=10, pady=8)
        hf.pack(fill="both", expand=True, padx=15, pady=8)
        self.history_list = tk.Listbox(hf, bg=c["bg"], fg=c["fg"], height=8); self.history_list.pack(fill="both", expand=True)
        self._refresh_history()

        if2 = tk.LabelFrame(f, text="💻 " + t("system_info"), bg=c["frame_bg"], fg=c["fg"], padx=15, pady=10)
        if2.pack(fill="x", padx=15, pady=8)
        for lbl, val in [(t("os"), f"{platform.system()} {platform.release()}"), (t("python"), platform.python_version()),
                         ("Version", "2.0.0"), ("CPU", platform.processor()), ("Arch", platform.machine())]:
            tk.Label(if2, text=f"{lbl}: {val}", bg=c["frame_bg"], fg=c["fg"]).pack(anchor="w", pady=2)
        return f

    def _save_profile(self):
        cfg.profile.username = self.v_username.get(); cfg.profile.email = self.v_email.get()
        cfg.profile.level = self.v_level.get(); cfg.save()
        self._log(t("profile_saved")); messagebox.showinfo(t("save"), t("profile_saved"))

    def _refresh_history(self):
        self.history_list.delete(0, tk.END)
        for h in reversed(scanner.stats.get("history", [])):
            self.history_list.insert(tk.END, f"{h.get('date','')} | {h.get('type','')} | {h.get('files',0)} files | {h.get('threats',0)} threats | {h.get('status','')}")

if __name__ == "__main__":
    root = tk.Tk(); ShieldProGUI(root); root.mainloop()
