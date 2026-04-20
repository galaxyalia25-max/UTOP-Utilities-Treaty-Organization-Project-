UTOP (Utilities Treaty Organization Project)

A collection of Python-based Windows utilities focused on system insight, productivity, and lightweight maintenance.

UTOP brings together multiple standalone tools into one cohesive project built around simplicity, performance, and local-first design.

🧰 Included Tools
🖥️ PC Health Dashboard

A real-time system monitoring tool:

Live CPU and memory usage graphs
Disk usage per drive
Running processes with CPU/RAM usage
Startup programs (Registry + Startup folders)
System uptime and OS details
🔍 Spotlight Search (App Launcher)

A fast, keyboard-driven Windows launcher inspired by Spotlight:

Search installed apps instantly
Fuzzy matching (partial & flexible search)
Minimal floating UI
Launch apps with Enter
Global hotkey: Ctrl + Space
Runs in system tray
Auto-indexes Start Menu shortcuts

Designed to be fast, minimal, and distraction-free.

📁 Office File Organizer

A simple file organization utility:

Scans Desktop & Downloads for Office files
Copies them into a structured folder
Creates a ZIP archive for backup or sharing
Handles duplicate filenames safely
🔐 Password Strength Checker

A local password analysis tool:

Real-time strength evaluation
Suggestions for stronger passwords
Entropy estimation
Optional advanced analysis (zxcvbn)
Fully offline (no data leaves your system)
🧹 Cleanup / Debloat Utilities (Experimental)

Advanced system utilities that can:

Remove temporary files
Modify startup entries
Disable telemetry features
Manage services and apps
Apply registry optimizations

⚠️ These tools interact with core Windows systems and should be used with caution.

⚙️ Requirements
Python 3.8 or newer
Windows OS
📦 Dependencies

Install everything with:

pip install psutil matplotlib customtkinter cryptography PyQt6 pynput pywin32
Optional
pip install zxcvbn
⚠️ Important Notice

Some tools in this project:

Modify the Windows Registry
Disable system services or features
Remove files or applications

Incorrect usage may cause system instability.

It is strongly recommended to:

Review the code before running
Create a system restore point
Use experimental tools carefully
🧠 Design Principles

UTOP is built around:

Lightweight tools (no unnecessary overhead)
Local-first execution (no cloud dependency)
Transparency (clear, understandable behavior)
Practicality (real everyday usefulness)
🖥️ Platform Support
Windows only
Uses Windows-specific APIs (winreg, win32com, etc.)
👤 Author

Created by WindowsPlayz_
