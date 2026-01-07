import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config

# --- Key Management ---
try:
    # The key from Config is a hex string, convert it to bytes
    ENCRYPTION_KEY = binascii.unhexlify(Config.AES_GCM_ENCRYPTION_KEY)
    # Initialize the AES-GCM object
    aesgcm = AESGCM(ENCRYPTION_KEY)
except (binascii.Error, ValueError):
    # Fallback/Error handling if key is invalid
    raise ValueError("Invalid AES_GCM_ENCRYPTION_KEY found in config. Must be 64 hexadecimal characters.")

# --- Encryption/Decryption Functions (AES-GCM) ---

def encrypt_data(data: str) -> str:
    """Encrypts a string using AES-GCM, returning IV + Ciphertext + Tag as a hex string."""
    if not data:
        return ""
    
    # 1. Generate a unique 12-byte Nonce (IV) for each encryption operation
    nonce = os.urandom(12) 
    
    # 2. Encrypt the data
    ciphertext_with_tag = aesgcm.encrypt(nonce, data.encode('utf-8'), associated_data=None)
    
    # 3. Combine Nonce (IV) and Ciphertext+Tag for storage
    full_cipher_text = nonce + ciphertext_with_tag
    
    # 4. Return as hex string for storage in a database column (Text/String)
    return full_cipher_text.hex()

def decrypt_data(hex_data: str) -> str:
    """Decrypts a hex string (IV + Ciphertext + Tag) using AES-GCM."""
    if not hex_data:
        return ""

    try:
        # Convert hex string back to bytes
        full_cipher_text = binascii.unhexlify(hex_data)
        
        # 1. Separate the Nonce (IV) - always the first 12 bytes
        nonce = full_cipher_text[:12]
        
        # 2. Separate the Ciphertext + Tag (the rest of the bytes)
        ciphertext_with_tag = full_cipher_text[12:]
        
        # 3. Decrypt the data (verification of tag happens here)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
        
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # Crucial for security: A failed decryption means the data was tampered with (GCM failure) or the key is wrong.
        return '[Decryption/Tamper Error]'