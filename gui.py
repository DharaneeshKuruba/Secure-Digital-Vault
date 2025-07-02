import os
import sys
import re
import shutil
import time
import subprocess
import threading
import sqlite3
from tkinter import filedialog, messagebox, simpledialog

import customtkinter as ctk
import bcrypt
import pyotp  # For TOTP MFA

import database
import auth
import otp_handler
import captcha_handler
import encryptor

# --- CONFIG ---
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
ALLOWED_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com"
}

MIN_FILE_SIZE = 1 * 1024           # 1 KB
MAX_FILE_SIZE = 5 * 1024 * 1024    # 5 MB

def is_valid_email(email: str) -> bool:
    """Check syntax and domain against whitelist."""
    if not EMAIL_REGEX.match(email):
        return False
    domain = email.split("@", 1)[1].lower()
    return domain in ALLOWED_DOMAINS

# --- DB HELPERS ---
def save_file_metadata(username, filename, path, salt):
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO files (username, filename, path, salt) VALUES (?, ?, ?, ?)",
        (username, filename, path, salt)
    )
    conn.commit()
    conn.close()

def get_user_files(username):
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute(
        "SELECT id, filename, path, salt FROM files WHERE username = ?",
        (username,)
    )
    rows = cur.fetchall()
    conn.close()
    return rows

def log_event(username, action, details=""):
    conn = sqlite3.connect('vault.db')
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs (username, action, details, timestamp) "
        "VALUES (?, ?, ?, datetime('now'))",
        (username, action, details)
    )
    conn.commit()
    conn.close()

# --- MAIN APP ---
class VaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Digital Vault")
        self.geometry("800x600")
        self.configure(fg_color="#1e1e1e")
        self.resizable(False, False)

        self.current_user = None
        self.generated_otp = None
        self.fp_generated_otp = None
        self.signup_otp_attempts = 0
        self.fp_otp_attempts = 0
        self.pwd_visible = False
        self.signup_pwd_visible = False

        database.setup_db()
        self.create_login_ui()

    # ---- LOGIN ----
    def create_login_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Secure Digital Vault",
                     font=("Arial", 28, "bold"),
                     text_color="#ffffff")\
            .pack(pady=(20,10))

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=400)
        self.username_entry.pack(pady=5)

        pwd_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        pwd_frame.pack(pady=5)
        self.password_entry = ctk.CTkEntry(pwd_frame,
                                           placeholder_text="Password",
                                           show="*", width=360)
        self.password_entry.pack(side="left")
        ctk.CTkButton(pwd_frame, text="👁️", width=40,
                      command=self.toggle_password_visibility)\
            .pack(side="left", padx=5)

        # CAPTCHA
        self.captcha = captcha_handler.generate_captcha()
        cap_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        cap_frame.pack(pady=5)
        self.captcha_label = ctk.CTkLabel(cap_frame,
                                          text=f"Captcha: {self.captcha}",
                                          font=("Arial",14),
                                          text_color="#cccccc")
        self.captcha_label.pack(side="left")
        ctk.CTkButton(cap_frame, text="Refresh", width=80,
                      command=self.refresh_captcha)\
            .pack(side="left", padx=5)
        self.captcha_entry = ctk.CTkEntry(self, placeholder_text="Enter Captcha", width=400)
        self.captcha_entry.pack(pady=5)

        for txt, cmd in [
            ("Login", self.login),
            ("Sign Up", self.create_signup_ui),
            ("Forgot Password", self.create_forgot_ui)
        ]:
            ctk.CTkButton(self, text=txt, width=200, command=cmd).pack(pady=5)

    def refresh_captcha(self):
        self.captcha = captcha_handler.generate_captcha()
        self.captcha_label.configure(text=f"Captcha: {self.captcha}")

    def toggle_password_visibility(self):
        self.pwd_visible = not self.pwd_visible
        self.password_entry.configure(show="" if self.pwd_visible else "*")

    def login(self):
        if self.captcha_entry.get() != self.captcha:
            return messagebox.showerror("Error","Invalid Captcha")

        user = self.username_entry.get().strip()
        pwd = self.password_entry.get()
        ok, msg = auth.verify_user(user, pwd)
        if not ok:
            return messagebox.showerror("Error", msg)

        # TOTP MFA
        secret = auth.get_user_mfa_secret(user)
        if not secret:
            return messagebox.showerror("Error","MFA not set up")
        pad = (8 - len(secret) % 8) % 8
        totp = pyotp.TOTP(secret + "=" * pad)
        code = simpledialog.askstring("MFA","Enter your 6-digit MFA code:")
        if not code or not totp.verify(code):
            return messagebox.showerror("Error","Invalid MFA code")

        self.current_user = user
        log_event(user, "login", "Logged in with MFA")
        messagebox.showinfo("Success","Login successful")
        self.create_vault_ui()

    # ---- SIGN-UP ----
    def create_signup_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Create Account",
                     font=("Arial",28,"bold"),
                     text_color="#ffffff")\
            .pack(pady=(20,10))

        self.new_username = ctk.CTkEntry(self, placeholder_text="Username", width=400)
        self.new_username.pack(pady=5)

        pwd_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        pwd_frame.pack(pady=5)
        self.new_password = ctk.CTkEntry(pwd_frame,
                                         placeholder_text="Password",
                                         show="*", width=360)
        self.new_password.pack(side="left")
        ctk.CTkButton(pwd_frame, text="👁️", width=40,
                      command=self.toggle_signup_password_visibility)\
            .pack(side="left", padx=5)

        self.email = ctk.CTkEntry(self, placeholder_text="Email", width=400)
        self.email.pack(pady=5)

        ctk.CTkButton(self, text="Send OTP", width=200,
                      command=self.send_signup_otp)\
            .pack(pady=5)
        self.otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP", width=400)
        self.otp_entry.pack(pady=5)

        ctk.CTkButton(self, text="Sign Up", width=200,
                      command=self.signup)\
            .pack(pady=10)
        ctk.CTkButton(self, text="Back to Login", width=200,
                      command=self.create_login_ui)\
            .pack(pady=5)

        self.signup_otp_attempts = 0

    def toggle_signup_password_visibility(self):
        self.signup_pwd_visible = not self.signup_pwd_visible
        self.new_password.configure(show="" if self.signup_pwd_visible else "*")

    def send_signup_otp(self):
        email = self.email.get().strip()
        if not is_valid_email(email):
            return messagebox.showerror(
                "Error",
                "Enter a valid email from: " + ", ".join(sorted(ALLOWED_DOMAINS))
            )
        if auth.user_exists(email):
            return messagebox.showerror("Error","Email already registered")

        self.generated_otp = otp_handler.generate_otp()
        otp_handler.send_otp(email, self.generated_otp)
        messagebox.showinfo("OTP Sent",f"OTP sent to {email}")

    def signup(self):
        otp = self.otp_entry.get().strip()
        if otp != self.generated_otp:
            self.signup_otp_attempts += 1
            if self.signup_otp_attempts > 2:
                messagebox.showerror("Error","Too many invalid OTPs—exiting")
                sys.exit(1)
            return messagebox.showerror("Error","Invalid OTP")

        user = self.new_username.get().strip()
        pwd = self.new_password.get()
        ok, msg = auth.validate_password(pwd)
        if not ok:
            return messagebox.showerror("Error", msg)

        success, msg = auth.create_user(user, self.email.get().strip(), pwd)
        if not success:
            return messagebox.showerror("Error", msg)

        # Setup TOTP MFA
        secret = auth.generate_mfa_secret(user)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user, issuer_name="SecureDigitalVault"
        )
        messagebox.showinfo(
            "MFA Setup",
            f"Scan this in your Authenticator app:\n\n{uri}"
        )

        log_event(user, "signup", "Account created & MFA configured")
        messagebox.showinfo("Success","Sign-up complete")
        self.create_login_ui()

    # ---- FORGOT PASSWORD ----
    def create_forgot_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Forgot Password",
                     font=("Arial",28,"bold"),
                     text_color="#ffffff")\
            .pack(pady=(20,10))

        self.fp_email = ctk.CTkEntry(self, placeholder_text="Email", width=400)
        self.fp_email.pack(pady=5)
        ctk.CTkButton(self, text="Send OTP", width=200,
                      command=self.send_fp_otp)\
            .pack(pady=5)
        self.fp_otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP", width=400)
        self.fp_otp_entry.pack(pady=5)
        self.new_fp_password = ctk.CTkEntry(self, placeholder_text="New Password",
                                            show="*", width=400)
        self.new_fp_password.pack(pady=5)
        ctk.CTkButton(self, text="Reset Password", width=200,
                      command=self.reset_fp_password)\
            .pack(pady=10)
        ctk.CTKButton(self, text="Back to Login", width=200,
                      command=self.create_login_ui)\
            .pack(pady=5)

        self.fp_otp_attempts = 0

    def send_fp_otp(self):
        email = self.fp_email.get().strip()
        if not is_valid_email(email):
            return messagebox.showerror(
                "Error",
                "Enter a valid email from: " + ", ".join(sorted(ALLOWED_DOMAINS))
            )
        if not auth.user_exists(email):
            return messagebox.showerror("Error","No such user")

        self.fp_generated_otp = otp_handler.generate_otp()
        otp_handler.send_otp(email, self.fp_generated_otp)
        messagebox.showinfo("OTP Sent",f"OTP sent to {email}")

    def reset_fp_password(self):
        otp = self.fp_otp_entry.get().strip()
        if otp != self.fp_generated_otp:
            self.fp_otp_attempts += 1
            if self.fp_otp_attempts > 2:
                messagebox.showerror("Error","Too many invalid OTPs—exiting")
                sys.exit(1)
            return messagebox.showerror("Error","Invalid OTP")

        new_pwd = self.new_fp_password.get()
        ok, msg = auth.validate_password(new_pwd)
        if not ok:
            return messagebox.showerror("Error", msg)

        auth.update_password(self.fp_email.get().strip(), new_pwd)
        messagebox.showinfo("Success","Password reset; please log in")
        self.create_login_ui()

    # ---- VAULT UI ----
    def create_vault_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text=f"Welcome, {self.current_user}!",
                     font=("Arial",20,"bold"),
                     text_color="#ffffff")\
            .pack(pady=20)

        for label, cmd in [
            ("Upload File", self.upload_file),
            ("List Files", self.list_files),
            ("Delete File", self.delete_file),
            ("Retrieve File", self.retrieve_file),
            ("Backup Vault", self.gui_backup),
            ("Restore Vault", self.gui_restore),
            ("Logout", self.create_login_ui),
        ]:
            ctk.CTkButton(self, text=label, width=300, height=40,
                          command=cmd).pack(pady=10)

    # ---- FILE OPS ----
    def upload_file(self):
        file_path = filedialog.askopenfilename(title="Select file")
        if not file_path:
            return

        filename = os.path.basename(file_path)
        # ensure exactly one “.” in the name
        if filename.count('.') != 1:
            return messagebox.showerror("Error","Invalid filename/extension")

        size = os.path.getsize(file_path)
        if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
            return messagebox.showerror(
                "Error",
                f"File must be between 1 KB and 5 MB"
            )

        dest = os.path.join(UPLOAD_FOLDER, filename)
        shutil.copy(file_path, dest)

        passphrase = simpledialog.askstring(
            "Encrypt Passphrase", "Enter passphrase:", show="*"
        )
        if not passphrase:
            return messagebox.showerror("Error","Passphrase required")

        enc_path, salt = encryptor.encrypt_file(dest, passphrase)
        os.remove(dest)
        save_file_metadata(self.current_user, filename, enc_path, salt)
        log_event(self.current_user, "upload", filename)
        messagebox.showinfo("Success","File encrypted & saved")

    def list_files(self):
        files = get_user_files(self.current_user)
        if not files:
            return messagebox.showinfo("Uploaded Files","No files")
        msg = "\n".join(f"{i+1}: {f[1]}" for i,f in enumerate(files))
        messagebox.showinfo("Uploaded Files", msg)

    def delete_file(self):
        files = get_user_files(self.current_user)
        if not files:
            return messagebox.showinfo("Info","No files to delete")
        msg = "\n".join(f"{i+1}: {f[1]}" for i,f in enumerate(files))
        choice = simpledialog.askinteger("Delete",f"Enter number:\n{msg}")
        if not choice or not (1 <= choice <= len(files)):
            return
        fid, path = files[choice-1][0], files[choice-1][2]
        if os.path.exists(path):
            os.remove(path)
        conn = sqlite3.connect('vault.db')
        conn.cursor().execute("DELETE FROM files WHERE id=?", (fid,))
        conn.commit(); conn.close()
        log_event(self.current_user, "delete", f"id={fid}")
        messagebox.showinfo("Success","Deleted")

    def retrieve_file(self):
        files = get_user_files(self.current_user)
        if not files:
            return messagebox.showinfo("Info","No files to retrieve")
        msg = "\n".join(f"{i+1}: {f[1]}" for i,f in enumerate(files))
        choice = simpledialog.askinteger("Retrieve",f"Enter number:\n{msg}")
        if not choice or not (1 <= choice <= len(files)):
            return
        fid, fn, salt = files[choice-1][0], files[choice-1][1], files[choice-1][3]
        enc_path = files[choice-1][2]

        passphrase = simpledialog.askstring("Decrypt Passphrase",
                                            "Enter passphrase:", show="*")
        if not passphrase:
            return messagebox.showerror("Error","Passphrase required")

        save_to = filedialog.asksaveasfilename(initialfile=fn)
        if not save_to:
            return

        try:
            encryptor.decrypt_file(enc_path, save_to, salt, passphrase)
            log_event(self.current_user, "retrieve", fn)
            messagebox.showinfo("Success", f"Saved to\n{save_to}")
        except Exception as e:
            messagebox.showerror("Error", f"Decrypt failed: {e}")

    # ---- BACKUP/RESTORE ----
    def gui_backup(self):
        encrypt = messagebox.askyesno("Encrypt?", "Encrypt backup with GPG?")
        gpg_pass = None
        if encrypt:
            gpg_pass = simpledialog.askstring("GPG Pass","Enter GPG pass:", show="*")
            if not gpg_pass:
                return messagebox.showerror("Error","Passphrase required")

        def worker():
            cmd = ["python","backup.py","backup"]
            if encrypt:
                cmd += ["--encrypt","--gpg-pass",gpg_pass]
            p = subprocess.run(cmd, capture_output=True, text=True)
            out = p.stdout.strip() or "✔ Backup OK"
            if p.returncode == 0:
                self.after(0, lambda: messagebox.showinfo("Backup", out))
            else:
                self.after(0, lambda: messagebox.showerror("Backup", p.stderr.strip() or "Failed"))

        threading.Thread(target=worker, daemon=True).start()

    def gui_restore(self):
        path = filedialog.askopenfilename(title="Select backup")
        if not path:
            return

        def worker():
            p = subprocess.run(
                ["python","backup.py","restore",path],
                capture_output=True, text=True
            )
            out = p.stdout.strip() or "✔ Restore OK"
            if p.returncode == 0:
                self.after(0, lambda: messagebox.showinfo("Restore", out))
            else:
                self.after(0, lambda: messagebox.showerror("Restore", p.stderr.strip() or "Failed"))

        threading.Thread(target=worker, daemon=True).start()

    def clear_window(self):
        for w in self.winfo_children():
            w.destroy()

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = VaultApp()
    app.mainloop()
