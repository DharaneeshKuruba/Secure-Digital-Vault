#!/usr/bin/env python3
import os
import tarfile
import time
import argparse
import subprocess
import getpass
import shutil

BACKUP_DIR = "backups"
VAULT_DB   = "vault.db"
UPLOADS    = "uploads"

def make_backup(encrypt=False, gpg_passphrase=None):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    archive_name = f"vault_backup_{ts}.tar.gz"
    tmp_archive  = os.path.join(BACKUP_DIR, archive_name)

    # 1) Create tar.gz of uploads/ and vault.db
    with tarfile.open(tmp_archive, "w:gz") as tar:
        if os.path.isdir(UPLOADS):
            tar.add(UPLOADS, arcname="uploads")
        if os.path.isfile(VAULT_DB):
            tar.add(VAULT_DB, arcname=VAULT_DB)
    print(f"[+] Backup created: {tmp_archive}")

    # 2) Optionally GPG-encrypt it
    if encrypt:
        if not gpg_passphrase:
            raise ValueError("GPG passphrase required for encryption")
        encrypted = tmp_archive + ".gpg"
        result = subprocess.run([
            "gpg", "--batch", "--passphrase", gpg_passphrase,
            "-c", "--cipher-algo", "AES256",
            "-o", encrypted, tmp_archive
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[!] GPG encryption failed:\n{result.stderr}")
            # leave the unencrypted archive in place, or decide to clean up
            return

        os.remove(tmp_archive)
        print(f"[+] Encrypted backup: {encrypted}")

def restore_backup(archive_path):
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"No such backup: {archive_path}")

    # If it's GPG-encrypted, decrypt
    if archive_path.endswith(".gpg"):
        decrypted = archive_path[:-4]
        passphrase = getpass.getpass("Enter GPG passphrase to decrypt backup: ")
        result = subprocess.run(
            ["gpg", "--batch", "--yes", "--decrypt", "--passphrase-fd", "0",
             "--output", decrypted, archive_path],
            input=passphrase + "\n",
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"[!] GPG decryption failed:\n{result.stderr}")
            return
        archive_path = decrypted

    # Unpack
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(".")
    print(f"[+] Restored backup from: {archive_path}")
    print("✔ Restore succeeded")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vault backup & restore")
    sub = parser.add_subparsers(dest="cmd")

    pb = sub.add_parser("backup", help="Create a backup")
    pb.add_argument("--encrypt", action="store_true", help="GPG-encrypt the archive")
    pb.add_argument("--gpg-pass", type=str, help="GPG passphrase for encryption")

    pr = sub.add_parser("restore", help="Restore from a backup")
    pr.add_argument("archive", type=str, help="Path to .tar.gz or .tar.gz.gpg backup")

    args = parser.parse_args()
    if args.cmd == "backup":
        make_backup(encrypt=args.encrypt, gpg_passphrase=args.gpg_pass)
    elif args.cmd == "restore":
        restore_backup(args.archive)
    else:
        parser.print_help()
