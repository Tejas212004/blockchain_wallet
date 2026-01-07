import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.getenv("SECRET_KEY", "A_VERY_LONG_FALLBACK_SECRET_KEY_REPLACE_ME")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///blockchain_wallet.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Cryptography Configuration (AES-GCM)
    AES_GCM_ENCRYPTION_KEY = os.getenv("AES_GCM_ENCRYPTION_KEY", "b40d6c4f0d3a5e8f1c9d2b7e0a6c5f4d8e2b7a1d5c3f0e9a7b4d1c0f8e3b2a5d")
    
    # Blockchain Configuration
    DIFFICULTY = 4  
    HASH_ALGORITHM = 'sha512'
    
    # Anomaly Detection Settings (Simple threshold for prototype)
    MAX_DAILY_TRANSACTIONS = 10
    HIGH_VALUE_THRESHOLD = 5000.00 