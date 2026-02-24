import math
import re
import tkinter as tk
from dataclasses import dataclass
from typing import List, Dict

import customtkinter as ctk

try:
    from zxcvbn import zxcvbn  # type: ignore
except ImportError:
    zxcvbn = None


COMMON_PASSWORDS = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "111111",
    "abc123",
    "password1",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "sunshine",
    "football",
}


@dataclass
class PasswordAnalysis:
    score: int
    strength_label: str
    feedback: List[str]
    requirements: Dict[str, bool]
    entropy_bits: float
    crack_time_display: str


def _estimate_entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    charset_size = 0
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return round(len(password) * math.log2(charset_size), 1)


def _length_score(length: int) -> float:
    if length <= 0:
        return 0.0
    if length < 12:
        return min(20.0, (length / 12.0) * 20.0)
    extra = min(length - 12, 12)
    return 20.0 + (extra / 12.0) * 20.0


def _variety_score(password: str) -> float:
    categories = 0
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    for flag in (has_upper, has_lower, has_digit, has_symbol):
        if flag:
            categories += 1
    return categories * 8.0


def _uniqueness_score(password: str) -> float:
    if not password:
        return 0.0
    length = len(password)
    unique_chars = len(set(password))
    ratio = unique_chars / float(length)
    clamped_ratio = max(0.0, min(1.0, ratio))
    return clamped_ratio * 20.0


def _base_requirements(password: str) -> Dict[str, bool]:
    length_ok = len(password) >= 12
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    if password:
        max_repeat = max(password.count(ch) for ch in set(password))
        repeated_ok = max_repeat <= len(password) // 2
    else:
        repeated_ok = False
    is_common = password.lower() in COMMON_PASSWORDS if password else False
    return {
        "length_ok": length_ok,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "repeated_ok": repeated_ok,
        "not_common": not is_common,
    }


def _strength_label_from_score(score: int) -> str:
    if score <= 20:
        return "Very weak"
    if score <= 40:
        return "Weak"
    if score <= 60:
        return "Okay"
    if score <= 80:
        return "Strong"
    return "Very strong"


def _build_feedback(password: str, requirements: Dict[str, bool]) -> List[str]:
    messages: List[str] = []
    if not password:
        messages.append("Enter a password to see its strength.")
        return messages
    if not requirements["length_ok"]:
        messages.append("Use at least 12 characters.")
    if not requirements["has_upper"]:
        messages.append("Add at least one uppercase letter (A–Z).")
    if not requirements["has_lower"]:
        messages.append("Add at least one lowercase letter (a–z).")
    if not requirements["has_digit"]:
        messages.append("Add at least one digit (0–9).")
    if not requirements["has_symbol"]:
        messages.append("Add at least one symbol (e.g. !, ?, #).")
    if not requirements["repeated_ok"]:
        messages.append("Avoid repeating the same characters too many times.")
    if not requirements["not_common"]:
        messages.append("Avoid common passwords that attackers try first.")
    if not messages:
        messages.append("All basic requirements are satisfied.")
        messages.append("Longer, more random passwords are even better.")
    return messages


def analyze_password(password: str) -> PasswordAnalysis:
    if password is None:
        password = ""
    try:
        requirements = _base_requirements(password)
        length_points = _length_score(len(password))
        variety_points = _variety_score(password)
        uniqueness_points = _uniqueness_score(password)
        score = length_points + variety_points + uniqueness_points
        if all(
            requirements[key]
            for key in (
                "length_ok",
                "has_upper",
                "has_lower",
                "has_digit",
                "has_symbol",
                "repeated_ok",
                "not_common",
            )
        ):
            score += 8.0
        if not requirements["not_common"]:
            score = min(score, 25.0)
        score = max(0, min(100, int(round(score))))
        entropy_bits = _estimate_entropy_bits(password)
        crack_time_display = "N/A"
        if zxcvbn is not None and password:
            try:
                result = zxcvbn(password)
                seconds = float(
                    result.get("crack_times_seconds", {}).get(
                        "offline_slow_hashing_1e4_per_second", 0.0
                    )
                )
                if seconds <= 0:
                    crack_time_display = "Instantly"
                elif seconds < 60:
                    crack_time_display = "Less than a minute"
                elif seconds < 3600:
                    crack_time_display = "Less than an hour"
                elif seconds < 86400:
                    crack_time_display = "Less than a day"
                elif seconds < 31557600:
                    crack_time_display = "Less than a year"
                else:
                    crack_time_display = "More than a year"
            except Exception:
                crack_time_display = "Unavailable"
        strength_label = _strength_label_from_score(score)
        feedback = _build_feedback(password, requirements)
        return PasswordAnalysis(
            score=score,
            strength_label=strength_label,
            feedback=feedback,
            requirements=requirements,
            entropy_bits=entropy_bits,
            crack_time_display=crack_time_display,
        )
    except Exception as exc:
        return PasswordAnalysis(
            score=0,
            strength_label="Error",
            feedback=[f"An error occurred while analyzing the password: {exc}"],
            requirements={
                "length_ok": False,
                "has_upper": False,
                "has_lower": False,
                "has_digit": False,
                "has_symbol": False,
                "repeated_ok": False,
                "not_common": True,
            },
            entropy_bits=0.0,
            crack_time_display="Unavailable",
        )


class PasswordStrengthApp:
    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self.root.title("Local Password Strength Checker")
        self.root.geometry("600x420")
        self.root.resizable(False, False)
        self.root.configure()
        self.password_var = tk.StringVar()
        self._build_ui()
        self._bind_events()
        self._update_display(analyze_password(""))

    def _build_ui(self) -> None:
        padding_x = 20
        padding_y = 10
        self.title_label = ctk.CTkLabel(
            self.root,
            text="Password Strength Checker",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        self.title_label.pack(pady=(20, 10))
        input_frame = ctk.CTkFrame(self.root)
        input_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))
        self.password_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter your password here",
            show="*",
            width=360,
            textvariable=self.password_var,
        )
        self.password_entry.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")
        self.show_password = False
        self.toggle_button = ctk.CTkButton(
            input_frame,
            text="Show",
            width=80,
            command=self._toggle_password_visibility,
        )
        self.toggle_button.grid(row=0, column=1, padx=(5, 10), pady=10)
        input_frame.grid_columnconfigure(0, weight=1)
        self.check_button = ctk.CTkButton(
            self.root,
            text="Check password",
            command=self._on_check_clicked,
        )
        self.check_button.pack(pady=(0, padding_y))
        strength_frame = ctk.CTkFrame(self.root)
        strength_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))
        self.strength_label = ctk.CTkLabel(
            strength_frame,
            text="Strength: Very weak",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.strength_label.pack(anchor="w", padx=10, pady=(10, 5))
        self.progress_bar = ctk.CTkProgressBar(strength_frame)
        self.progress_bar.pack(fill="x", padx=10, pady=(0, 10))
        self.progress_bar.set(0.0)
        self.entropy_label = ctk.CTkLabel(
            strength_frame,
            text="Estimated entropy: 0 bits",
            font=ctk.CTkFont(size=12),
        )
        self.entropy_label.pack(anchor="w", padx=10, pady=(0, 10))
        feedback_frame = ctk.CTkFrame(self.root)
        feedback_frame.pack(fill="both", expand=True, padx=padding_x, pady=(0, padding_y))
        feedback_title = ctk.CTkLabel(
            feedback_frame,
            text="Feedback and missing requirements:",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        feedback_title.pack(anchor="w", padx=10, pady=(10, 5))
        self.feedback_text = ctk.CTkTextbox(
            feedback_frame,
            height=130,
        )
        self.feedback_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.feedback_text.configure(state="disabled")
        self.notice_label = ctk.CTkLabel(
            self.root,
            text=(
                "All checks are performed locally on this device.\n"
                "Passwords are never logged, saved, or transmitted anywhere."
            ),
            justify="center",
            font=ctk.CTkFont(size=11),
        )
        self.notice_label.pack(pady=(0, 5))
        self.error_label = ctk.CTkLabel(
            self.root,
            text="",
            text_color="#ff6b6b",
            font=ctk.CTkFont(size=11),
        )
        self.error_label.pack(pady=(0, 10))

    def _bind_events(self) -> None:
        self.password_var.trace_add("write", self._on_password_changed)
        self.password_entry.bind("<Return>", lambda _event: self._on_check_clicked())

    def _toggle_password_visibility(self) -> None:
        self.show_password = not self.show_password
        if self.show_password:
            self.password_entry.configure(show="")
            self.toggle_button.configure(text="Hide")
        else:
            self.password_entry.configure(show="*")
            self.toggle_button.configure(text="Show")

    def _on_password_changed(self, *_args: object) -> None:
        self._run_analysis()

    def _on_check_clicked(self) -> None:
        self._run_analysis()

    def _run_analysis(self) -> None:
        password = self.password_var.get()
        try:
            analysis: PasswordAnalysis = analyze_password(password)
        except Exception as exc:
            self.error_label.configure(text=f"Error while analyzing password: {exc}")
            return
        self.error_label.configure(text="")
        self._update_display(analysis)

    def _update_display(self, analysis: PasswordAnalysis) -> None:
        score = max(0, min(100, analysis.score))
        progress_value = score / 100.0
        self.progress_bar.set(progress_value)
        if score <= 40:
            bar_color = "#ff4b4b"
        elif score <= 70:
            bar_color = "#ffd93d"
        else:
            bar_color = "#4caf50"
        self.progress_bar.configure(progress_color=bar_color)
        self.strength_label.configure(text=f"Strength: {analysis.strength_label}")
        entropy_text = f"Estimated entropy: {analysis.entropy_bits} bits"
        if analysis.crack_time_display and analysis.crack_time_display != "N/A":
            entropy_text += f" | Estimated crack time: {analysis.crack_time_display}"
        self.entropy_label.configure(text=entropy_text)
        self.feedback_text.configure(state="normal")
        self.feedback_text.delete("1.0", "end")
        for line in analysis.feedback:
            self.feedback_text.insert("end", f"• {line}\n")
        self.feedback_text.configure(state="disabled")


def create_app() -> ctk.CTk:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    root = ctk.CTk()
    PasswordStrengthApp(root)
    return root


def main() -> None:
    root = create_app()
    root.mainloop()


if __name__ == "__main__":
    main()

