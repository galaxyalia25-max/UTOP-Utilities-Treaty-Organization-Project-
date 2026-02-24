import os
import zipfile
import glob
from pathlib import Path
import shutil
import tkinter as tk
from tkinter import ttk, messagebox

class OfficeFileOrganizer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Office File Organizer")
        self.geometry("800x600")
        
        self.downloads_path = str(Path.home()) + '/Downloads'
        self.desktop_path = str(Path.home()) + '/Desktop'
        self.office_dir = self.downloads_path + '/office_files'
        self.zip_file = self.desktop_path + '/office_files.zip'
        
        self.create_widgets()
        
    def create_widgets(self):
        title_label = tk.Label(self, text="Office File Organizer", font=("Arial", 16))
        title_label.pack(pady=10)
        
        status_frame = tk.Frame(self)
        status_frame.pack(pady=10)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = tk.Label(status_frame, textvariable=self.status_var)
        status_label.pack()
        
        self.progress = ttk.Progressbar(status_frame, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        
        process_btn = tk.Button(button_frame, text="Organize Files", command=self.organize_files)
        process_btn.pack(side=tk.LEFT, padx=5)
        
        exit_btn = tk.Button(button_frame, text="Exit", command=self.destroy)
        exit_btn.pack(side=tk.LEFT, padx=5)
        
    def organize_files(self):
        self.status_var.set("Scanning...")
        self.update_idletasks()
        
        extensions = ['*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx']
        files_found = False
        
        for ext in extensions:
            downloads_files = glob.glob(os.path.join(self.downloads_path, ext))
            desktop_files = glob.glob(os.path.join(self.desktop_path, ext))
            
            if downloads_files or desktop_files:
                files_found = True
                break
                
        if not files_found:
            self.status_var.set("No Office files found!")
            return
            
        if not os.path.exists(self.office_dir):
            os.makedirs(self.office_dir)
            
        copied_files = []
        for ext in extensions:
            for src_path in glob.glob(os.path.join(self.downloads_path, ext)) + glob.glob(os.path.join(self.desktop_path, ext)):
                filename = os.path.basename(src_path)
                
                base_name, ext = os.path.splitext(filename)
                counter = 1
                new_filename = filename
                
                while os.path.exists(os.path.join(self.office_dir, new_filename)):
                    new_filename = f"{base_name}_{counter}{ext}"
                    counter += 1
                    
                dest_path = os.path.join(self.office_dir, new_filename)
                shutil.copy(src_path, dest_path)
                copied_files.append(dest_path)
                self.status_var.set(f"Copied: {new_filename}")
                self.update_idletasks()
                
        if copied_files:
            with zipfile.ZipFile(self.zip_file, 'w') as zipf:
                for file in copied_files:
                    zipf.write(file, os.path.basename(file))
                    
            self.status_var.set(f"Archive created: {self.zip_file}")
            messagebox.showinfo("Success", f"Files organized and archived to:\n{self.zip_file}")
        else:
            if os.path.exists(self.office_dir):
                os.rmdir(self.office_dir)
            self.status_var.set("No files were processed.")
            
    def run(self):
        self.mainloop()

if __name__ == "__main__":
    app = OfficeFileOrganizer()
    app.run()