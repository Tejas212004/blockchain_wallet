import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("ENCRYPTION_KEY")
if not key:
    raise ValueError("ENCRYPTION_KEY not found in environment")
fernet = Fernet(key.encode())