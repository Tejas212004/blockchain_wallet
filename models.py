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
    # Stored using a strong hash function (e.g., pbkdf2:sha256 or bcrypt), as required by the paper
    password_hash = db.Column(db.String(200), nullable=False)
    # TOTP secret is now encrypted (ciphertext in hex) for security
    encrypted_totp_secret = db.Column(db.String(256), nullable=True) 
    role = db.Column(db.String(20), default='customer')
    
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
        # FIX: Removed the problematic 'method=bcrypt' argument.
        # werkzeug will now use the default, strong hashing algorithm (usually pbkdf2:sha256).
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# This model replaces the simple 'Transaction' table
class BlockModel(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    index = db.Column(db.Integer, nullable=False, unique=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Store transaction data (encrypted notes, amount, recipient, etc.) as serialized JSON
    data = db.Column(db.Text, nullable=False) 
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    nonce = db.Column(db.Integer, nullable=False)  # Proof of Work nonce
    
    # Cryptographic Links (SHA-512)
    # The project uses SHA-512 for better security than SHA-256 [cite: 20, 190]
    current_hash = db.Column(db.String(128), nullable=False, unique=True)
    previous_hash = db.Column(db.String(128), nullable=False)