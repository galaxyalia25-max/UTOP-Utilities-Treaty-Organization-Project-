import os
import sys
import winreg
import json
import logging
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import ctypes
import subprocess
import tempfile
import shutil

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('registry_cleaner.log'),
        logging.StreamHandler()
    ]
)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class RegistryCleanerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Registry Cleaner")
        self.geometry("800x600")
        
        self.appdata = os.path.join(Path.home(), 'AppData', 'Roaming')
        self.uninstall_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        self.backup_file = os.path.join(Path.home(), f'registry_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.reg')
        
        if not is_admin():
            self.request_admin_privileges()
            return
            
        self.create_widgets()
        
    def request_admin_privileges(self):
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            self.destroy()
        except Exception as e:
            logging.error(f"Failed to request admin privileges: {e}")
            messagebox.showerror("Error", "Failed to request admin privileges")
            self.destroy()
        
    def create_widgets(self):
        title_label = tk.Label(self, text="Registry Cleaner", font=("Arial", 16))
        title_label.pack(pady=10)
        
        status_frame = tk.Frame(self)
        status_frame.pack(pady=10)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = tk.Label(status_frame, textvariable=self.status_var)
        status_label.pack()
        
        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        results_frame = tk.Frame(self)
        results_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        
        self.process_btn = tk.Button(button_frame, text="Start Cleanup", command=self.start_cleanup)
        self.process_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = tk.Button(button_frame, text="Cancel", state=tk.DISABLED, command=self.cancel_cleanup)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        exit_btn = tk.Button(button_frame, text="Exit", command=self.destroy)
        exit_btn.pack(side=tk.LEFT, padx=5)
        
        self.cleanup_thread = None
        self.cancel_flag = False
        
    def log_message(self, msg):
        self.results_text.insert(tk.END, f"{msg}\n")
        self.results_text.see(tk.END)
        self.update_idletasks()
        
    def start_cleanup(self):
        self.process_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.cancel_flag = False
        
        self.cleanup_thread = threading.Thread(target=self.cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
    def cancel_cleanup(self):
        self.cancel_flag = True
        self.status_var.set("Cancelling...")
        self.progress['value'] = 0
        self.update_idletasks()
        
    def cleanup_worker(self):
        try:
            self.status_var.set("Scanning registry keys...")
            self.progress['value'] = 20
            self.update_idletasks()
            
            orphaned_keys = self.scan_registry_keys()
            
            self.status_var.set("Scanning AppData files...")
            self.progress['value'] = 40
            self.update_idletasks()
            
            orphaned_files = self.scan_appdata()
            
            self.display_results(orphaned_keys, orphaned_files)
            
            if orphaned_keys or orphaned_files:
                result = messagebox.askyesno(
                    "Confirm Deletion",
                    f"Found {len(orphaned_keys)} registry keys and {len(orphaned_files)} AppData files.\n\n"
                    f"Do you want to delete these items?"
                )
                
                if result and not self.cancel_flag:
                    self.status_var.set("Creating registry backup...")
                    self.progress['value'] = 60
                    self.update_idletasks()
                    
                    self.create_key_backup(orphaned_keys)
                    
                    self.status_var.set("Deleting registry keys...")
                    self.progress['value'] = 80
                    self.update_idletasks()
                    
                    self.remove_orphaned_keys(orphaned_keys)
                    
                    self.status_var.set("Deleting AppData files...")
                    self.progress['value'] = 90
                    self.update_idletasks()
                    
                    self.remove_orphaned_files(orphaned_files)
                    
                    self.status_var.set("Cleanup completed successfully!")
                    self.progress['value'] = 100
                    self.update_idletasks()
                    
                    messagebox.showinfo(
                        "Cleanup Complete",
                        f"Registry cleanup completed!\n\n"
                        f"Backup saved to: {self.backup_file}\n"
                        f"Deleted {len(orphaned_keys)} registry keys and {len(orphaned_files)} AppData files."
                    )
                else:
                    self.status_var.set("Cleanup cancelled by user.")
            else:
                self.status_var.set("No orphaned items found.")
                messagebox.showinfo("Cleanup Complete", "No orphaned registry keys or AppData files found.")
                
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.progress['value'] = 0
            self.process_btn.config(state=tk.NORMAL)
            self.cancel_btn.config(state=tk.DISABLED)
            
    def create_key_backup(self, orphaned_keys):
        try:
            with open(self.backup_file, 'w', encoding='utf-16') as f:
                f.write("Windows Registry Editor Version 5.00\n\n")
                for hive, key_path in orphaned_keys:
                    self._backup_key(hive, key_path, f)
            self.log_message(f"Registry backup created: {self.backup_file}")
        except Exception as e:
            self.log_message(f"Error creating backup: {e}")
            
    def _backup_key(self, hive, key_path, file_obj):
        try:
            key = winreg.OpenKey(hive, key_path)
            hive_str = "HKEY_CURRENT_USER" if hive == winreg.HKEY_CURRENT_USER else "HKEY_LOCAL_MACHINE"
            file_obj.write(f"[{hive_str}\\{key_path}]\n")
            
            i = 0
            while True:
                try:
                    name, value, type_ = winreg.EnumValue(key, i)
                    file_obj.write(self._format_value(name, value, type_))
                    i += 1
                except OSError:
                    break
                    
            winreg.CloseKey(key)
            self.log_message(f"Backed up key: {hive_str}\\{key_path}")
        except Exception as e:
            self.log_message(f"Error backing up key {key_path}: {e}")
            
    def _format_value(self, name, value, type_):
        if name == "":
            name = "@"
        if type_ == winreg.REG_SZ:
            return f'"{name}"="{value}"\n'
        elif type_ == winreg.REG_DWORD:
            return f'"{name}"=dword:{value:08x}\n'
        elif type_ == winreg.REG_BINARY:
            hex_values = ",".join(f"{b:02x}" for b in value)
            return f'"{name}"=hex:{hex_values}\n'
        elif type_ == winreg.REG_EXPAND_SZ:
            return f'"{name}"=hex(2):{",".join(format(ord(c), "02x") for c in value + "\\0")}\n'
        elif type_ == winreg.REG_MULTI_SZ:
            joined = "\\0".join(value) + "\\0\\0"
            return f'"{name}"=hex(7):{",".join(format(ord(c), "02x") for c in joined)}\n'
        elif type_ == winreg.REG_QWORD:
            return f'"{name}"=qword:{value:016x}\n'
        return f'"{name}"="{value}"\n'
            
    def scan_registry_keys(self):
        orphaned_keys = []
        try:
            targets = [
                r'Software\Microsoft\Windows\CurrentVersion\Run',
                r'Software\Microsoft\Windows\CurrentVersion\RunOnce'
            ]
            
            for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                for subkey in targets:
                    try:
                        reg_key = winreg.OpenKey(hive, subkey)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(reg_key, i)
                                if self._has_orphaned_reference(value):
                                    orphaned_keys.append((hive, subkey))
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(reg_key)
                    except:
                        continue
        except Exception as e:
            logging.error(f"Registry scanning error: {e}")
        return list(set(orphaned_keys))
    
    def _has_orphaned_reference(self, value):
        try:
            installed = self.get_installed_programs()
            val = str(value).lower()
            return val and not any(prog in val for prog in installed)
        except:
            return False
    
    def scan_appdata(self):
        orphaned_files = []
        installed_programs = set(self.get_installed_programs())
        
        for root, dirs, files in os.walk(self.appdata):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                name = dir_name.lower()
                
                if any(prog in name for prog in installed_programs):
                    continue
                
                try:
                    contents = os.listdir(dir_path)
                    if len(contents) <= 1:
                        continue
                    
                    orphaned_files.append(dir_path)
                except:
                    continue
                    
        return orphaned_files
    
    def display_results(self, orphaned_keys, orphaned_files):
        self.results_text.delete(1.0, tk.END)
        
        self.results_text.insert(tk.END, "ORPHANED REGISTRY KEYS:\n")
        if orphaned_keys:
            for hive, key_path in orphaned_keys:
                hive_str = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                self.results_text.insert(tk.END, f"{hive_str}\\{key_path}\n")
        else:
            self.results_text.insert(tk.END, "None\n")
            
        self.results_text.insert(tk.END, "\nORPHANED APPDATA DIRECTORIES:\n")
        if orphaned_files:
            for file_path in orphaned_files:
                self.results_text.insert(tk.END, f"{file_path}\n")
        else:
            self.results_text.insert(tk.END, "None\n")
            
        self.results_text.see(tk.END)
        
    def remove_orphaned_keys(self, orphaned_keys):
        for hive, key_path in orphaned_keys:
            try:
                self._recursive_delete_key(hive, key_path)
                self.log_message(f"Removed registry key: {key_path}")
            except Exception as e:
                self.log_message(f"Failed to remove key {key_path}: {e}")
    
    def _recursive_delete_key(self, hive, key_path):
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
            subkeys = []
            
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
            
            for sub in subkeys:
                self._recursive_delete_key(hive, f"{key_path}\\{sub}")
            
            winreg.CloseKey(key)
            winreg.DeleteKey(hive, key_path)
        except:
            pass
            
    def remove_orphaned_files(self, orphaned_files):
        for file_path in orphaned_files:
            try:
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path, ignore_errors=True)
                else:
                    os.remove(file_path)
                self.log_message(f"Removed orphaned file/directory: {file_path}")
            except Exception as e:
                self.log_message(f"Failed to remove file/directory {file_path}: {e}")
    
    def get_installed_programs(self):
        programs = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.uninstall_key)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                        programs.append(display_name.lower())
                    except:
                        pass
                    winreg.CloseKey(subkey)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            logging.error(f"Error reading uninstall registry: {e}")
        return programs
    
    def run(self):
        self.mainloop()

if __name__ == "__main__":
    app = RegistryCleanerGUI()
    app.run()
