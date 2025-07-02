# Secure-Digital-Vault# 🔐 Secure Digital Vault

Secure Digital Vault is a privacy-focused application that enables users to securely store, backup, and manage their files. It incorporates multi-factor authentication (MFA), strong cryptographic encryption using **scrypt** and **AES-256**, and secure file handling functionalities including upload, download, backup, restore, and delete.

---

## 🚀 Features

- 🔐 Secure user authentication with **multi-factor authentication (MFA)**
- 📁 Encrypted file upload and download
- 🛡️ Data encryption using **scrypt** (for key derivation) and **AES-256**
- 💾 Secure backup and restore functionality
- 🗑️ Option to permanently delete files from the encrypted database
- ⚙️ Minimalistic and secure user interface

---

## 🛠️ Tech Stack

- **Frontend**: Pyhton
- **Backend**: Python Flask
- **Database**: SQL Lite
- **Encryption**: scrypt (key derivation) + AES-256 (file encryption)
- **Authentication**: MFA with email OTP & TOTP 

---

## 📦 Installation & Setup

bash
# Clone the repository
> git clone https://github.com/DharaneeshKuruba/Secure-Digital-Vault.git

# Navigate to the project directory
> cd Secure-Digital-Vault

# Install backend dependencies
> pip install -r requirements.txt (if using Python)

# Start the server
> python3 server.py
# Start the app
> python3 main.py




Login page:


![WhatsApp Image 2025-07-02 at 14 42 14 (1)](https://github.com/user-attachments/assets/e4f1b0a8-b99f-46da-9946-c1ab46bc2a02)

Signup page:


![WhatsApp Image 2025-07-02 at 14 42 12 (1)](https://github.com/user-attachments/assets/3e111046-1b69-4e6a-8060-cec1ab2856b9)

MFA code:


![WhatsApp Image 2025-07-02 at 14 42 11 (2)](https://github.com/user-attachments/assets/8b64db47-1b1c-48c8-86b0-49a698ecf0bb)

Home page:


![WhatsApp Image 2025-07-02 at 14 42 11](https://github.com/user-attachments/assets/9d2d2c67-2634-4f7f-8edd-42bfde12a617)

Encryption passphrase:


![WhatsApp Image 2025-07-02 at 14 42 12](https://github.com/user-attachments/assets/a88da7eb-be70-44e6-8c53-86f20ddf1e33)

File encrypted:


![WhatsApp Image 2025-07-02 at 14 42 13](https://github.com/user-attachments/assets/f59c4583-8f00-4c52-b857-57f82743b1a8)

Decryption passphrase:


![WhatsApp Image 2025-07-02 at 14 42 11 (1)](https://github.com/user-attachments/assets/4080d165-323a-4884-ab4b-5ec630933928)

File decrypted:


![WhatsApp Image 2025-07-02 at 14 42 14](https://github.com/user-attachments/assets/9354b57e-1ab9-4afa-8958-9d2aa2ec1649)
