from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from encryption import decrypt_data, encrypt_data 

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    
    # Stored using a strong hash function (e.g., pbkdf2:sha256 or bcrypt)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # TOTP secret is now encrypted (ciphertext in hex) for security
    encrypted_totp_secret = db.Column(db.String(256), nullable=True) 
    
    # 🔥 CORRECTION: Increased size from 20 to 30 to safely accommodate 'super_admin'
    role = db.Column(db.String(30), default='customer') 

    # NEW: Flag to force a password change (for provisioned admins)
    needs_password_change = db.Column(db.Boolean, default=False) 
    
    blocks = db.relationship('BlockModel', backref='user', lazy=True)

    @property
    def totp_secret(self):
        """Decrypts and returns the TOTP secret."""
        if self.encrypted_totp_secret:
            return decrypt_data(self.encrypted_totp_secret)
        return None

    @totp_secret.setter
    def totp_secret(self, secret):
        """Encrypts and sets the TOTP secret."""
        self.encrypted_totp_secret = encrypt_data(secret)

    def set_password(self, password):
        """Sets the password_hash using Werkzeug's secure hashing."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies the provided password against the stored hash."""
        return check_password_hash(self.password_hash, password)

# This model replaces the simple 'Transaction' table
class BlockModel(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    index = db.Column(db.Integer, nullable=False, unique=True)
    
    # 🔥 CORRECTION: Set nullable=True to allow the Genesis Block (which has no user)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Store transaction data (encrypted notes, amount, recipient, etc.) as serialized JSON
    data = db.Column(db.Text, nullable=False) 
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    nonce = db.Column(db.Integer, nullable=False)  # Proof of Work nonce
    
    # Cryptographic Links (SHA-512)
    current_hash = db.Column(db.String(128), nullable=False, unique=True)
    previous_hash = db.Column(db.String(128), nullable=False)