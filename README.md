# ShieldPro AntiVirus v2.0

<div align="center">

**Enterprise-Grade Antivirus Protection for Windows**

Built by RuGuard

![License](https://img.shields.io/badge/License-MIT-orange)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-yellow)

</div>

## 📋 Overview

ShieldPro is a modern antivirus solution featuring:
- 🔍 **Signature-based Scanner** - Fast pattern matching detection
- 📛 **Quarantine System** - Secure threat isolation with restore/delete
- 📜 **Event Logging** - Complete activity audit trail
- 🖥️ **Modern PyQt6 GUI** - Clean, dark-themed interface with 3 themes
- 👤 **User Profile** - Scan history and system information
- ⚙️ **Advanced Settings** - Import/export configurations, exclusions, performance tuning

## 🚀 Quick Start

### Pre-built Executable
```
dist\ShieldPro.exe
```

### Build from Source
```powershell
.\setup.ps1
```

Or manually:
```powershell
pip install -r requirements.txt
pyinstaller --onefile --name ShieldPro src\gui\shieldpro.py
```

## 🧪 Testing

Create EICAR test file to verify detection:
```powershell
"X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > test.com
```

## 📦 Project Structure

```
ShieldPro/
├── src/
│   ├── engine/         # C signature scanner (DLL)
│   ├── heuristic/      # Rust heuristic analysis (DLL)
│   ├── monitor/        # C++ system monitor (DLL)
│   ├── updater/        # Go update client (DLL)
│   ├── database.py     # SQLite database module
│   └── gui/
│       ├── shieldpro.py       # PyQt6 version (primary)
│       └── shieldpro_tk.py   # Tkinter fallback
├── modules/            # Native DLLs
├── data/
│   ├── signatures/     # Virus signature database
│   ├── quarantine/     # Isolated threats
│   └── logs/           # Event logs
├── dist/               # Built executables
├── setup.ps1           # Build script
├── requirements.txt    # Python dependencies
└── README.md
```

## ⚙️ Settings

### General
- Autostart, real-time protection, auto-update
- USB protection, firewall toggle

### Scanning
- Max file size, scan depth, thread count
- File type filters (.exe, .dll, docs, archives)
- Heuristic analysis, auto-quarantine
- Path and extension exclusions

### Appearance
- 3 themes: Dark, Light, Blue
- Language: Russian / English
- Adjustable font size

### Import/Export
- Export all settings to JSON
- Import settings from backup

## 📝 Features

| Feature | Status |
|---------|--------|
| Quick Scan | ✅ |
| Full Scan | ✅ |
| Custom Scan | ✅ |
| Pause/Resume Scan | ✅ |
| Signature Database | ✅ |
| Quarantine (restore/delete) | ✅ |
| Event Logging | ✅ |
| Scan History | ✅ |
| User Profile | ✅ |
| Settings Import/Export | ✅ |
| 3 Themes | ✅ |
| System Tray | ✅ |

## 📄 License

MIT License - Copyright (c) 2024 RuGuard

## 🔐 Security Note

This is a demonstration antivirus. For production use, comprehensive security testing and certification is required.
