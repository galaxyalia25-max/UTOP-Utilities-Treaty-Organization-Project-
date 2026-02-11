import os
import sys
import ctypes
import subprocess
import winreg
import shutil
import tempfile

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

protected = {
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.MicrosoftEdge",
    "Microsoft.MicrosoftEdgeWebView2Runtime",
    "Microsoft.ShellExperienceHost",
    "Microsoft.StartMenuExperienceHost",
    "Microsoft.Windows.Cortana",
    "Microsoft.Windows.Search",
    "Microsoft.WindowsCalculator",
    "Microsoft.WindowsNotepad",
    "Microsoft.WindowsTerminal",
    "Microsoft.Windows.SecHealthUI",
    "Microsoft.AAD.BrokerPlugin",
    "Microsoft.AccountsControl",
    "Microsoft.LockApp",
    "Microsoft.Windows.CloudExperienceHost"
}

def run_ps(cmd):
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def create_restore():
    run_ps("Checkpoint-Computer -Description 'Extreme Debloat Backup' -RestorePointType MODIFY_SETTINGS")

def disable_telemetry():
    keys = [
        (r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
        (r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableTelemetry", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1)
    ]
    for path, name, val in keys:
        k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
        winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
        winreg.CloseKey(k)

def disable_tracking_tasks():
    tasks = [
        "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "Microsoft\\Windows\\Feedback\\Siuf\\DmClient"
    ]
    for t in tasks:
        subprocess.run(["schtasks", "/Change", "/TN", t, "/Disable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def remove_services():
    services = [
        "DiagTrack",
        "dmwappushservice",
        "WMPNetworkSvc",
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc",
        "MapsBroker"
    ]
    for s in services:
        subprocess.run(["sc", "stop", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sc", "config", s, "start=disabled"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def remove_apps():
    cmd = "Get-AppxPackage | Select Name"
    res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        name = line.strip()
        if name and all(p not in name for p in protected):
            run_ps(f"Get-AppxPackage {name} | Remove-AppxPackage")

def remove_onedrive():
    subprocess.run(["taskkill", "/f", "/im", "OneDrive.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["%SystemRoot%\\SysWOW64\\OneDriveSetup.exe", "/uninstall"], shell=True)

def disable_widgets_copilot():
    keys = [
        (r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds", "EnableFeeds", 0),
        (r"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows\Copilot", "TurnOffWindowsCopilot", 1)
    ]
    for path, name, val in keys:
        k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
        winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
        winreg.CloseKey(k)

def cleanup_temp():
    dirs = [
        tempfile.gettempdir(),
        os.path.expandvars("%LOCALAPPDATA%\\Temp"),
        os.path.expandvars("%SYSTEMROOT%\\Temp")
    ]
    for d in dirs:
        if os.path.exists(d):
            for f in os.listdir(d):
                p = os.path.join(d, f)
                try:
                    if os.path.isfile(p) or os.path.islink(p):
                        os.unlink(p)
                    elif os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                except:
                    pass

def main():
    create_restore()
    disable_telemetry()
    disable_tracking_tasks()
    remove_services()
    remove_apps()
    remove_onedrive()
    disable_widgets_copilot()
    cleanup_temp()
    print("DONE. RESTART RECOMMENDED.")

if __name__ == "__main__":
    main()
