import os
import threading
import tkinter.filedialog as fd
import tkinter.messagebox as mb

import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken


class FileEncryptorApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("Secure File Encryptor / Decryptor")
        self.geometry("780x420")
        self.minsize(720, 380)

        self.file_path: str | None = None
        self.operation_mode: ctk.StringVar = ctk.StringVar(value="encrypt")
        self.key_var: ctk.StringVar = ctk.StringVar()

        self._configure_grid()
        self._build_ui()

    def _configure_grid(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=2)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def _build_ui(self) -> None:
        header_frame = ctk.CTkFrame(self)
        header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="nsew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Secure File Encryptor / Decryptor",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title_label.grid(row=0, column=0, pady=(10, 0), sticky="n")

        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="File Encryption Tool V1.0",
            font=ctk.CTkFont(size=14),
        )
        subtitle_label.grid(row=1, column=0, pady=(4, 10), sticky="n")

        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        for i in range(4):
            main_frame.grid_rowconfigure(i, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        mode_frame = ctk.CTkFrame(main_frame)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))
        mode_frame.grid_columnconfigure((0, 1, 2), weight=1)

        mode_label = ctk.CTkLabel(
            mode_frame,
            text="Mode",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        mode_label.grid(row=0, column=0, padx=(10, 0), pady=10, sticky="w")

        encrypt_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Encrypt",
            variable=self.operation_mode,
            value="encrypt",
            command=self._on_mode_change,
        )
        encrypt_radio.grid(row=0, column=1, pady=10, sticky="e")

        decrypt_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Decrypt",
            variable=self.operation_mode,
            value="decrypt",
            command=self._on_mode_change,
        )
        decrypt_radio.grid(row=0, column=2, pady=10, padx=(0, 10), sticky="e")

        file_frame = ctk.CTkFrame(main_frame)
        file_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        file_frame.grid_columnconfigure(0, weight=1)
        file_frame.grid_columnconfigure(1, weight=0)

        self.file_label = ctk.CTkLabel(
            file_frame,
            text="No file selected",
            anchor="w",
        )
        self.file_label.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.file_button = ctk.CTkButton(
            file_frame,
            text="Select File",
            command=self._select_file,
            width=140,
        )
        self.file_button.grid(row=0, column=1, padx=10, pady=10, sticky="e")

        key_frame = ctk.CTkFrame(main_frame)
        key_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        key_frame.grid_columnconfigure(0, weight=1)
        key_frame.grid_columnconfigure(1, weight=0)
        key_frame.grid_columnconfigure(2, weight=0)

        key_label = ctk.CTkLabel(
            key_frame,
            text="Encryption Key",
            anchor="w",
        )
        key_label.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")

        self.key_entry = ctk.CTkEntry(
            key_frame,
            textvariable=self.key_var,
            placeholder_text="Paste or load Fernet key here",
        )
        self.key_entry.grid(row=1, column=0, padx=10, pady=(5, 10), sticky="ew")

        gen_key_button = ctk.CTkButton(
            key_frame,
            text="Generate & Save Key",
            command=self._generate_and_save_key,
            width=150,
        )
        gen_key_button.grid(row=1, column=1, padx=(5, 5), pady=(5, 10))

        upload_key_button = ctk.CTkButton(
            key_frame,
            text="Upload Key",
            command=self._upload_key,
            width=120,
        )
        upload_key_button.grid(row=1, column=2, padx=(5, 10), pady=(5, 10))

        action_frame = ctk.CTkFrame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))
        action_frame.grid_columnconfigure(0, weight=1)
        action_frame.grid_columnconfigure(1, weight=1)

        self.action_button = ctk.CTkButton(
            action_frame,
            text="Encrypt File",
            height=40,
            command=self._start_operation_thread,
        )
        self.action_button.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")
        bottom_frame.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            bottom_frame,
            text="Ready.",
            anchor="w",
        )
        self.status_label.grid(row=0, column=0, padx=10, pady=(10, 4), sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(bottom_frame, mode="determinate")
        self.progress_bar.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.progress_bar.set(0)

    def _on_mode_change(self) -> None:
        mode = self.operation_mode.get()
        if mode == "encrypt":
            self.file_button.configure(text="Select File")
            self.action_button.configure(text="Encrypt File")
            self.status_label.configure(text="Ready to encrypt a file.")
        else:
            self.file_button.configure(text="Select .locked File")
            self.action_button.configure(text="Decrypt File")
            self.status_label.configure(text="Ready to decrypt a .locked file.")

    def _select_file(self) -> None:
        mode = self.operation_mode.get()
        if mode == "encrypt":
            path = fd.askopenfilename(title="Select file to encrypt")
        else:
            path = fd.askopenfilename(
                title="Select file to decrypt",
                filetypes=[("Locked Files", "*.locked"), ("All Files", "*.*")],
            )
        if not path:
            return
        self.file_path = path
        display_name = os.path.basename(path)
        self.file_label.configure(text=display_name)
        if mode == "encrypt":
            self.status_label.configure(text="File selected for encryption.")
        else:
            self.status_label.configure(text="File selected for decryption.")

    def _generate_and_save_key(self) -> None:
        try:
            key = Fernet.generate_key()
            save_path = fd.asksaveasfilename(
                title="Save key file",
                defaultextension=".key",
                filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
            )
            if not save_path:
                self.status_label.configure(text="Key generation cancelled.")
                return
            with open(save_path, "wb") as key_file:
                key_file.write(key)
            self.key_var.set(key.decode("utf-8"))
            self.status_label.configure(text="New encryption key generated and saved.")
            mb.showinfo("Key Saved", "Encryption key generated and saved successfully.")
        except Exception as exc:
            self.status_label.configure(text="Failed to generate or save key.")
            mb.showerror("Error", f"An error occurred while generating/saving the key:\n{exc}")

    def _upload_key(self) -> None:
        path = fd.askopenfilename(
            title="Select key file",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "rb") as key_file:
                key_data = key_file.read().strip()
            self.key_var.set(key_data.decode("utf-8"))
            self.status_label.configure(text="Key loaded from file.")
            mb.showinfo("Key Loaded", "Key file loaded successfully.")
        except Exception as exc:
            self.status_label.configure(text="Failed to load key file.")
            mb.showerror("Error", f"Could not load key file:\n{exc}")

    def _get_key_bytes(self) -> bytes | None:
        key_text = self.key_var.get().strip()
        if not key_text:
            mb.showwarning("Missing Key", "Please generate, upload, or paste an encryption key.")
            self.status_label.configure(text="No encryption key set.")
            return None
        try:
            return key_text.encode("utf-8")
        except Exception:
            mb.showerror("Invalid Key", "The key format is invalid.")
            self.status_label.configure(text="Invalid key format.")
            return None

    def _start_operation_thread(self) -> None:
        if not self.file_path:
            mb.showwarning("No File Selected", "Please select a file first.")
            self.status_label.configure(text="No file selected.")
            return

        key_bytes = self._get_key_bytes()
        if key_bytes is None:
            return

        mode = self.operation_mode.get()

        self.action_button.configure(state="disabled")
        self.file_button.configure(state="disabled")
        self.progress_bar.set(0)
        self.update_idletasks()

        if mode == "encrypt":
            self.status_label.configure(text="Encrypting file...")
            target = self._encrypt_file
        else:
            self.status_label.configure(text="Decrypting file...")
            target = self._decrypt_file

        thread = threading.Thread(target=self._run_operation_safe, args=(target, key_bytes), daemon=True)
        thread.start()

    def _run_operation_safe(self, operation, key_bytes: bytes) -> None:
        try:
            self._update_progress(0.3)
            operation(key_bytes)
            self._update_progress(1.0)
        except InvalidToken:
            self._set_status_threadsafe("Invalid key or corrupted encrypted file.")
            self._show_message_threadsafe(
                "Decryption Failed",
                "The key is invalid for this file, or the file data is corrupted.",
                error=True,
            )
        except Exception as exc:
            self._set_status_threadsafe("Operation failed. See details.")
            self._show_message_threadsafe("Error", f"An unexpected error occurred:\n{exc}", error=True)
        finally:
            self._reset_controls_threadsafe()

    def _update_progress(self, value: float) -> None:
        def callback() -> None:
            self.progress_bar.set(value)
        self.after(0, callback)

    def _set_status_threadsafe(self, text: str) -> None:
        def callback() -> None:
            self.status_label.configure(text=text)
        self.after(0, callback)

    def _show_message_threadsafe(self, title: str, message: str, error: bool = False) -> None:
        def callback() -> None:
            if error:
                mb.showerror(title, message)
            else:
                mb.showinfo(title, message)
        self.after(0, callback)

    def _reset_controls_threadsafe(self) -> None:
        def callback() -> None:
            self.action_button.configure(state="normal")
            self.file_button.configure(state="normal")
            self.progress_bar.set(0)
        self.after(0, callback)

    def _encrypt_file(self, key_bytes: bytes) -> None:
        if not self.file_path:
            self._set_status_threadsafe("No file selected for encryption.")
            return

        fernet = Fernet(key_bytes)
        in_path = self.file_path
        directory = os.path.dirname(in_path)
        original_name = os.path.basename(in_path)
        separator = b"::"

        with open(in_path, "rb") as source_file:
            original_data = source_file.read()

        combined_plaintext = original_name.encode("utf-8") + separator + original_data
        encrypted_token = fernet.encrypt(combined_plaintext)

        out_name = original_name + ".locked"
        out_path = os.path.join(directory, out_name)

        with open(out_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_token)

        self._set_status_threadsafe("File encrypted successfully.")
        self._show_message_threadsafe(
            "Encryption Complete",
            f"File encrypted successfully as:\n{out_path}",
            error=False,
        )

    def _decrypt_file(self, key_bytes: bytes) -> None:
        if not self.file_path:
            self._set_status_threadsafe("No file selected for decryption.")
            return

        fernet = Fernet(key_bytes)
        in_path = self.file_path

        with open(in_path, "rb") as encrypted_file:
            encrypted_token = encrypted_file.read()

        decrypted_combined = fernet.decrypt(encrypted_token)

        separator = b"::"
        name_bytes, original_data = decrypted_combined.split(separator, 1)
        original_name = name_bytes.decode("utf-8")

        directory = os.path.dirname(in_path)
        out_path = os.path.join(directory, original_name)

        if os.path.exists(out_path):
            base, ext = os.path.splitext(original_name)
            out_path = os.path.join(directory, f"{base}_decrypted{ext}")

        with open(out_path, "wb") as restored_file:
            restored_file.write(original_data)

        self._set_status_threadsafe("File decrypted successfully.")
        self._show_message_threadsafe(
            "Decryption Complete",
            f"File decrypted successfully as:\n{out_path}",
            error=False,
        )


def main() -> None:
    app = FileEncryptorApp()
    app.mainloop()


if __name__ == "__main__":
    main()

