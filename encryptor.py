import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a 32-byte key from a passphrase and salt using PBKDF2HMAC.
    The resulting key is URL-safe base64-encoded for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path: str, passphrase: str) -> tuple[str, bytes]:
    """
    Encrypts the file at file_path using a key derived from the provided passphrase
    and a randomly generated salt.

    Returns:
        A tuple containing:
          - The path to the encrypted file (original file + ".enc")
          - The salt (16 bytes) used in key derivation.
    """
    # Generate a random salt (16 bytes)
    salt = os.urandom(16)
    key = generate_key(passphrase, salt)
    f = Fernet(key)

    with open(file_path, "rb") as infile:
        data = infile.read()

    encrypted_data = f.encrypt(data)
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as outfile:
        outfile.write(encrypted_data)

    print(f"File '{file_path}' encrypted successfully to '{encrypted_path}'.")
    return encrypted_path, salt

def decrypt_file(encrypted_path: str, output_path: str, salt: bytes, passphrase: str) -> None:
    """
    Decrypts the file at encrypted_path using the provided salt and passphrase,
    then writes the decrypted data to output_path.
    """
    key = generate_key(passphrase, salt)
    f = Fernet(key)
    with open(encrypted_path, "rb") as infile:
        encrypted_data = infile.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(output_path, "wb") as outfile:
        outfile.write(decrypted_data)
    print(f"File '{encrypted_path}' decrypted successfully to '{output_path}'.")
