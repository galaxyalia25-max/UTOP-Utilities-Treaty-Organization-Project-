# UTOP (Utilities Treaty Organization Project)

A collection of Python-based Windows utility tools designed to improve system awareness, productivity, and basic maintenance through lightweight, local applications.

UTOP combines multiple standalone utilities into one unified project focused on clarity, control, and practicality.

---

## 🧰 Included Tools

### 🖥️ PC Health Dashboard

A real-time system monitoring tool that provides:

- Live CPU and memory usage graphs  
- Disk usage per drive  
- Running processes with CPU/RAM usage  
- Startup programs (Registry + Startup folders)  
- System uptime and OS information  

---

### 🔍 Spotlight Search (Windows Launcher)

A fast, keyboard-driven app launcher inspired by macOS Spotlight:

- Instantly search installed apps  
- Fuzzy search (partial and flexible matching)  
- Clean floating UI  
- Launch apps with Enter  
- Global hotkey (**Ctrl + Space**)  
- System tray integration  
- Automatically scans Start Menu shortcuts  

---

### 📁 Office File Organizer

A file management utility that:

- Scans Desktop and Downloads for Office documents  
- Copies them into a dedicated folder  
- Creates a ZIP archive for easy storage and transfer  
- Handles duplicate filenames safely  

---

### 🔐 Password Strength Checker

A local password analysis tool that:

- Evaluates password strength in real time  
- Provides improvement suggestions  
- Estimates entropy (password randomness)  
- Optionally uses advanced analysis via `zxcvbn`  
- Runs fully offline with no data transmission  

---

### 🧹 Windows Cleanup / Debloat Utilities (Experimental)

System optimization tools that may:

- Remove temporary files  
- Modify startup entries  
- Disable telemetry and tracking features  
- Manage system services and apps  
- Perform registry changes for optimization  

⚠️ These tools perform system-level changes and should be used carefully.

---

## ⚙️ Requirements

- Python 3.8+  
- Windows OS  

---

## 📦 Dependencies

Install required libraries:
pip install psutil matplotlib customtkinter cryptography PyQt6 pynput pywin32

---

## ⚠️ Important Warning

Some UTOP tools:

- Modify system registry  
- Remove system files or apps  
- Disable Windows services/features  

These actions can affect system stability if misused.

**Always review code before running and ensure you understand its behavior.**

Creating a system restore point is strongly recommended before using cleanup utilities.

---

## 🧠 Project Goals

UTOP is built around:

- Lightweight, single-purpose utilities  
- Local-first processing (no cloud dependency)  
- Transparency in system operations  
- Practical tools for everyday Windows use  

---

## 🖥️ Platform Support

- Windows only (uses Windows-specific APIs like `winreg`, `win32com`)

---

## 👤 Author

Made by WindowsPlayz_ with love ❤️
