import os
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

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def save_file_metadata(filename, path, salt):
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (filename, path, salt) VALUES (?, ?, ?)",
        (filename, path, salt)
    )
    conn.commit()
    conn.close()

def get_uploaded_files():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, path, salt FROM files")
    files = cursor.fetchall()
    conn.close()
    return files

def log_event(username, action, details=""):
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (username, action, details, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (username, action, details)
    )
    conn.commit()
    conn.close()

class VaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry("800x600")
        self.title("Secure Digital Vault")
        self.configure(fg_color="#1e1e1e")
        self.resizable(False, False)

        self.generated_otp = None
        self.fp_generated_otp = None
        self.current_user = None
        self.pwd_visible = False
        self.signup_pwd_visible = False

        database.setup_db()
        self.create_login_ui()

    def create_login_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Secure Digital Vault", font=("Arial", 28, "bold"),
                     text_color="#ffffff").pack(pady=(20, 10))

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=400, height=40)
        self.username_entry.pack(pady=10)

        pwd_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        pwd_frame.pack(pady=10)
        self.password_entry = ctk.CTkEntry(pwd_frame, placeholder_text="Password",
                                           width=360, height=40, show="*")
        self.password_entry.pack(side="left")
        ctk.CTkButton(pwd_frame, text="👁️", width=40,
                      command=self.toggle_password_visibility).pack(side="left", padx=5)

        self.captcha = captcha_handler.generate_captcha()
        captcha_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        captcha_frame.pack(pady=5)
        self.captcha_label = ctk.CTkLabel(captcha_frame, text=f"Captcha: {self.captcha}",
                                         font=("Arial", 14), text_color="#cccccc")
        self.captcha_label.pack(side="left")
        ctk.CTkButton(captcha_frame, text="Refresh", width=80,
                      command=self.refresh_captcha).pack(side="left", padx=5)

        self.captcha_entry = ctk.CTkEntry(self, placeholder_text="Enter Captcha",
                                          width=400, height=40)
        self.captcha_entry.pack(pady=5)

        for text, cmd in [
            ("Login", self.login),
            ("Sign Up", self.create_signup_ui),
            ("Forgot Password", self.forgot_password_ui)
        ]:
            ctk.CTkButton(self, text=text, width=200, height=40,
                          command=cmd).pack(pady=5)

    def refresh_captcha(self):
        self.captcha = captcha_handler.generate_captcha()
        self.captcha_label.configure(text=f"Captcha: {self.captcha}")

    def toggle_password_visibility(self):
        self.pwd_visible = not self.pwd_visible
        self.password_entry.configure(show="" if self.pwd_visible else "*")

    def create_signup_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Create New Account", font=("Arial", 28, "bold"),
                     text_color="#ffffff").pack(pady=(20, 10))

        self.new_username = ctk.CTkEntry(self, placeholder_text="New Username", width=400, height=40)
        self.new_username.pack(pady=10)

        signup_pwd_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        signup_pwd_frame.pack(pady=10)
        self.new_password = ctk.CTkEntry(signup_pwd_frame, placeholder_text="New Password",
                                         width=360, height=40, show="*")
        self.new_password.pack(side="left")
        ctk.CTkButton(signup_pwd_frame, text="👁️", width=40,
                      command=self.toggle_signup_password_visibility).pack(side="left", padx=5)

        self.email = ctk.CTkEntry(self, placeholder_text="Email", width=400, height=40)
        self.email.pack(pady=10)

        ctk.CTkButton(self, text="Send OTP", width=200, height=40,
                      command=self.send_otp).pack(pady=10)
        self.otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP", width=400, height=40)
        self.otp_entry.pack(pady=10)

        ctk.CTkButton(self, text="Sign Up", width=200, height=40,
                      command=self.signup).pack(pady=10)
        ctk.CTkButton(self, text="Already have an account? Login", width=200, height=40,
                      command=self.create_login_ui).pack(pady=10)

    def toggle_signup_password_visibility(self):
        self.signup_pwd_visible = not self.signup_pwd_visible
        self.new_password.configure(show="" if self.signup_pwd_visible else "*")

    def forgot_password_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text="Forgot Password", font=("Arial", 28, "bold"),
                     text_color="#ffffff").pack(pady=(20, 10))

        self.fp_email = ctk.CTkEntry(self, placeholder_text="Enter your email", width=400, height=40)
        self.fp_email.pack(pady=10)
        ctk.CTkButton(self, text="Send OTP", width=200, height=40,
                      command=self.fp_send_otp).pack(pady=10)
        self.fp_otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP", width=400, height=40)
        self.fp_otp_entry.pack(pady=10)
        self.new_fp_password = ctk.CTkEntry(self, placeholder_text="Enter new password",
                                            width=400, height=40, show="*")
        self.new_fp_password.pack(pady=10)
        ctk.CTkButton(self, text="Reset Password", width=200, height=40,
                      command=self.fp_reset_password).pack(pady=10)
        ctk.CTkButton(self, text="Back to Login", width=200, height=40,
                      command=self.create_login_ui).pack(pady=10)

    def fp_send_otp(self):
        email = self.fp_email.get()
        if not email:
            messagebox.showerror("Error", "Please enter an email address")
            return
        if not auth.user_exists(email):
            messagebox.showerror("Error", "No user found with this email.")
            return
        self.fp_generated_otp = otp_handler.generate_otp()
        try:
            otp_handler.send_otp(email, self.fp_generated_otp)
            messagebox.showinfo("OTP Sent", f"An OTP has been sent to {email}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send OTP: {e}")
            self.fp_generated_otp = None

    def fp_reset_password(self):
        email = self.fp_email.get()
        entered_otp = self.fp_otp_entry.get()
        new_password = self.new_fp_password.get()
        if not self.fp_generated_otp:
            messagebox.showerror("Error", "Please click 'Send OTP' first!")
            return
        if entered_otp != self.fp_generated_otp:
            messagebox.showerror("Error", "Invalid OTP")
            return
        valid, msg = auth.validate_password(new_password)
        if not valid:
            messagebox.showerror("Error", msg)
            return
        old_hash = auth.get_password_hash(email)
        if old_hash and bcrypt.checkpw(new_password.encode('utf-8'), old_hash):
            messagebox.showerror("Error", "New password must differ from the old one.")
            return
        auth.update_password(email, new_password)
        otp_handler.send_reset_password(email, new_password)
        messagebox.showinfo("Success", "Password reset successfully. Please log in.")
        self.create_login_ui()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        captcha_input = self.captcha_entry.get()

        if captcha_input != self.captcha:
            messagebox.showerror("Error", "Invalid Captcha")
            return

        success, msg = auth.verify_user(username, password)
        if not success:
            messagebox.showerror("Error", msg)
            return

        mfa_secret = auth.get_user_mfa_secret(username)
        if not mfa_secret:
            messagebox.showerror("Error", "MFA not set up for this user.")
            return

        padding = (8 - len(mfa_secret) % 8) % 8
        mfa_secret += "=" * padding

        totp = pyotp.TOTP(mfa_secret)
        code = simpledialog.askstring("MFA Authentication", "Enter your MFA code:")
        if not code or not totp.verify(code):
            messagebox.showerror("Error", "MFA verification failed.")
            return

        self.current_user = username
        log_event(username, "login", f"User logged in at {time.ctime()} with MFA")
        messagebox.showinfo("Success", "Login Successful")
        self.create_vault_ui()

    def send_otp(self):
        email = self.email.get()
        if not email:
            messagebox.showerror("Error", "Please enter an email address")
            return
        if auth.user_exists(email):
            messagebox.showerror("Error", "Email already in use.")
            return
        self.generated_otp = otp_handler.generate_otp()
        try:
            otp_handler.send_otp(email, self.generated_otp)
            messagebox.showinfo("OTP Sent", f"OTP sent to {email}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send OTP: {e}")
            self.generated_otp = None

    def signup(self):
        username = self.new_username.get()
        password = self.new_password.get()
        email = self.email.get()
        entered_otp = self.otp_entry.get()

        if not self.generated_otp:
            messagebox.showerror("Error", "Click ‘Send OTP’ first!")
            return

        valid, msg = auth.validate_password(password)
        if not valid:
            messagebox.showerror("Error", msg)
            return

        if entered_otp != self.generated_otp:
            messagebox.showerror("Error", "Invalid OTP")
            return

        success, msg = auth.create_user(username, email, password)
        if not success:
            messagebox.showerror("Error", msg)
            return

        log_event(username, "signup", f"New user created at {time.ctime()}")
        messagebox.showinfo("Success", "Sign Up Successful")
        self.generated_otp = None
        self.create_login_ui()

    def create_vault_ui(self):
        self.clear_window()
        ctk.CTkLabel(self, text=f"Welcome, {self.current_user}!",
                     font=("Arial", 20, "bold"), text_color="#ffffff").pack(pady=20)

        for label, cmd in [
            ("Upload File", self.upload_file),
            ("List Files", self.list_files),
            ("Delete File", self.delete_file),
            ("Retrieve File", self.retrieve_file),
            ("Backup Vault", self.gui_backup),
            ("Restore Vault", self.gui_restore),
            ("Logout", self.create_login_ui),
        ]:
            ctk.CTkButton(self, text=label, width=300, height=40, command=cmd).pack(pady=10)

    def upload_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if not file_path:
            return
        filename = os.path.basename(file_path)
        dest = os.path.join(UPLOAD_FOLDER, filename)
        shutil.copy(file_path, dest)

        passphrase = simpledialog.askstring(
            "Encryption Passphrase", "Enter passphrase for encryption:", show="*"
        )
        if not passphrase:
            messagebox.showerror("Error", "Passphrase required.")
            return

        encrypted_path, salt = encryptor.encrypt_file(dest, passphrase)
        os.remove(dest)
        save_file_metadata(filename, encrypted_path, salt)
        log_event(self.current_user, "upload", f"Uploaded {filename}")
        messagebox.showinfo("Success", "File encrypted & saved.")

    def list_files(self):
        files = get_uploaded_files()
        msg = "\n".join(f"{i+1}: {f[1]}" for i, f in enumerate(files)) if files else "No files uploaded."
        messagebox.showinfo("Uploaded Files", msg)

    def delete_file(self):
        files = get_uploaded_files()
        if not files:
            messagebox.showinfo("Info", "No files to delete.")
            return
        msg = "\n".join(f"{i+1}: {f[1]}" for i, f in enumerate(files))
        choice = simpledialog.askinteger("Delete File", f"Enter number to delete:\n{msg}")
        if not choice or not (1 <= choice <= len(files)):
            return
        fid = files[choice-1][0]

        conn = sqlite3.connect('vault.db')
        cur = conn.cursor()
        cur.execute("SELECT path FROM files WHERE id=?", (fid,))
        row = cur.fetchone()
        if row and os.path.exists(row[0]):
            os.remove(row[0])
        cur.execute("DELETE FROM files WHERE id=?", (fid,))
        conn.commit()
        conn.close()

        log_event(self.current_user, "delete", f"Deleted file id={fid}")
        messagebox.showinfo("Success", "File deleted.")

    def retrieve_file(self):
        files = get_uploaded_files()
        if not files:
            messagebox.showinfo("Info", "No files to retrieve.")
            return
        msg = "\n".join(f"{i+1}: {f[1]}" for i, f in enumerate(files))
        choice = simpledialog.askinteger("Retrieve File", f"Enter number to retrieve:\n{msg}")
        if not choice or not (1 <= choice <= len(files)):
            return
        fid, filename, salt = files[choice-1][0], files[choice-1][1], files[choice-1][3]

        enc_pass = simpledialog.askstring(
            "Decryption Passphrase", "Enter the encryption passphrase:", show="*"
        )
        if not enc_pass:
            messagebox.showerror("Error", "Passphrase required.")
            return

        save_to = filedialog.asksaveasfilename(initialfile=filename, title="Save Decrypted File")
        if not save_to:
            return

        try:
            encryptor.decrypt_file(files[choice-1][2], save_to, salt, enc_pass)
            log_event(self.current_user, "retrieve", f"Retrieved {filename}")
            messagebox.showinfo("Success", f"File decrypted to:\n{save_to}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def gui_backup(self):
        encrypt = messagebox.askyesno("Encrypt Backup", "Encrypt backup with GPG?")
        gpg_pass = None
        if encrypt:
            gpg_pass = simpledialog.askstring("GPG Passphrase", "Enter GPG passphrase:", show="*")
            if not gpg_pass:
                messagebox.showerror("Error", "GPG passphrase required.")
                return

        def worker():
            cmd = ["python", "backup.py", "backup"]
            if encrypt:
                cmd += ["--encrypt", "--gpg-pass", gpg_pass]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            out = proc.stdout.strip() or "✔ Backup succeeded"
            if proc.returncode == 0:
                self.after(0, lambda: messagebox.showinfo("Backup Complete", out))
            else:
                err = proc.stderr.strip() or "Backup failed"
                self.after(0, lambda: messagebox.showerror("Backup Failed", err))

        threading.Thread(target=worker, daemon=True).start()

    def gui_restore(self):
        path = filedialog.askopenfilename(title="Select backup archive")
        if not path:
            return

        def worker():
            cmd = ["python", "backup.py", "restore", path]
            proc = subprocess.run(cmd, capture_output=True, text=True, input="")
            out = proc.stdout.strip() or "✔ Restore succeeded"
            if proc.returncode == 0:
                self.after(0, lambda: messagebox.showinfo("Restore Complete", out))
            else:
                err = proc.stderr.strip() or "Restore failed"
                self.after(0, lambda: messagebox.showerror("Restore Failed", err))

        threading.Thread(target=worker, daemon=True).start()

    def clear_window(self):
        for w in self.winfo_children():
            w.destroy()

if __name__ == "__main__":
    app = VaultApp()
    app.mainloop()
