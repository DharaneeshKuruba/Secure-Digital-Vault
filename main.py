from gui import VaultApp
import database
import os
from encryptor import generate_key

# Check if encryption key exists; if not, generate one.
if not os.path.exists("key.key"):
    generate_key()

if __name__ == "__main__":
    database.setup_db()
    app = VaultApp()
    app.mainloop()
