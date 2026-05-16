# ShieldPro AntiVirus

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
- 📛 **Quarantine System** - Secure threat isolation
- 📜 **Event Logging** - Complete activity audit trail
- 🖥️ **Modern GUI** - Clean, dark-themed interface

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
pip install pyinstaller
pyinstaller --onefile --name ShieldPro src\gui\shieldpro_tk.py
```

## 🧪 Testing

Create EICAR test file to verify detection:
```powershell
# Create test file
"X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > test.com

# Scan with ShieldPro - should detect as EICAR virus
```

## 📦 Project Structure

```
ShieldPro/
├── src/
│   ├── engine/         # C signature scanner (DLL)
│   ├── heuristic/      # Rust heuristic analysis (DLL)
│   ├── monitor/        # C++ system monitor (DLL)
│   ├── updater/       # Go update client (DLL)
│   └── gui/
│       ├── shieldpro.py      # PyQt5 version (needs Python 3.8-3.12)
│       └── shieldpro_tk.py  # Tkinter version (works with any Python)
├── modules/            # Native DLLs (require compilation)
├── data/
│   ├── signatures/     # Virus signature database
│   ├── quarantine/     # Isolated threats
│   └── logs/          # Event logs
├── dist/              # Built executables
├── setup.ps1          # Build script
├── requirements.txt   # Python dependencies
└── README.md
```

## 🔧 Building Native Modules (Optional)

For full functionality with native DLLs:

1. **C Engine** (scanner.c):
   ```bash
   gcc -shared -o engine.dll scanner.c -O2
   ```

2. **Rust Heuristic** (src/heuristic/):
   ```bash
   cargo build --release
   ```

3. **C++ Monitor** (src/monitor/):
   ```bash
   cl /LD monitor.cpp
   ```

4. **Go Updater** (src/updater/):
   ```bash
   go build -buildmode=c-shared
   ```

## ⚙️ Requirements

- **Python**: 3.8+
- **No external dependencies** (uses built-in Tkinter)

For PyQt5 version (better UI):
- Python 3.8-3.12
- PyQt5

## 📝 Features

| Feature | Status |
|---------|--------|
| Quick Scan | ✅ |
| Full Scan | ✅ |
| Custom Scan | ✅ |
| Signature Database | ✅ |
| Quarantine | ✅ |
| Event Logging | ✅ |
| Dark Theme UI | ✅ |

## 📄 License

MIT License - Copyright (c) 2024 RuGuard

## 🔐 Security Note

This is a demonstration antivirus. For production use, comprehensive security testing and certification is required.