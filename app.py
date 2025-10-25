from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
import os
import pyotp
import json
from datetime import datetime
from config import Config
from models import db, User, BlockModel
from forms import TransactionForm
from encryption import decrypt_data, encrypt_data
# FIX 1: Import the 'Block' class directly to fix the AttributeError in load_chain_from_db
from blockchain import Blockchain, Block 
import qrcode
import io
import base64

# --- Blockchain and App Setup ---

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

# Initialize in-memory blockchain instance
blockchain = Blockchain()

# --- Custom Decorator ---

def admin_required(f):
    """Decorator to restrict access to admin users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Administrator access required.", 'danger')
            return redirect(url_for('dashboard_redirect')) # Redirect non-admins away
        return f(*args, **kwargs)
    return decorated_function

# --- Placeholder for Anomaly Detection (Mandated by Paper) ---

def anomaly_detection_check(transaction_data, user_id):
    """
    Placeholder for ML-driven anomaly detection. 
    Currently implements simple rule-based checks based on Config.
    """
    amount = transaction_data.get('amount', 0)
    
    # Simple check 1: High value transaction
    if amount > Config.HIGH_VALUE_THRESHOLD:
        print(f"ANOMALY ALERT: High value transaction detected for User {user_id}: {amount}")
        flash("Warning: High-value transaction detected. System is monitoring.", 'warning')
    
    return True

# --- Helper Functions ---

def load_chain_from_db():
    """Loads all blocks from the database into the in-memory blockchain."""
    with app.app_context():
        blocks_from_db = BlockModel.query.order_by(BlockModel.index.asc()).all()
        
        if not blocks_from_db:
            print("No blocks found in DB. Creating Genesis Block...")
            genesis_block = blockchain.chain[0]
            # Since user_id 1 might not exist yet, we assign it for integrity.
            db_block = BlockModel(
                index=genesis_block.index,
                user_id=1, 
                data=genesis_block.data,
                timestamp=datetime.strptime(genesis_block.timestamp, '%Y-%m-%d %H:%M:%S'),
                nonce=genesis_block.nonce,
                current_hash=genesis_block.hash,
                previous_hash=genesis_block.previous_hash
            )
            db.session.add(db_block)
            db.session.commit()
            blocks_from_db.append(db_block)

        blockchain.chain = []
        for db_block in blocks_from_db:
            # FIX 2: Use the directly imported 'Block' class 
            reconstructed_block = Block( 
                index=db_block.index,
                data=db_block.data,
                previous_hash=db_block.previous_hash,
                nonce=db_block.nonce,
                timestamp=db_block.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            )
            reconstructed_block.hash = db_block.current_hash
            blockchain.chain.append(reconstructed_block)
        
        print(f"Blockchain loaded with {len(blockchain.chain)} blocks.")

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        totp_code = request.form.get('totp')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            
            # --- START: FIX TO BREAK TOTP SETUP LOOP ---
            # NOTE: This block remains as it handles the initial setup case securely.
            if not user.totp_secret or user.totp_secret == '[Decryption/Tamper Error]':
                login_user(user)
                flash("Please set up TOTP to continue.", 'warning')
                return redirect(url_for('setup_totp'))
            # --- END: FIX TO BREAK TOTP SETUP LOOP ---

            # Normal TOTP verification logic starts here
            
            # ✅ RESTORED: Check for TOTP code presence
            if not totp_code:
                # If secret exists but code is blank, logout the user to enforce TOTP entry
                logout_user() 
                flash("TOTP code is required for login.", 'danger')
                return render_template('login.html')

            # ✅ RESTORED: Verify TOTP code
            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code):
                logout_user()
                flash("Invalid TOTP code.", 'danger')
                return render_template('login.html')

            # Successful login with TOTP
            login_user(user)
            session['totp_verified'] = True
            flash("Login successful.", 'success')
            
            # ✅ RESTORED: Redirect to the dashboard
            return redirect(url_for('dashboard_redirect'))

        flash("Invalid email or password.", 'danger')
        return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already registered.", 'danger')
            return redirect(url_for('register'))

        # NEW LOGIC: ALL PUBLIC REGISTRATIONS ARE CUSTOMER
        user_role = 'customer' 
        
        # SPECIAL CASE: Initial registration (must be assigned admin manually after setup)
        if not User.query.first():
            flash("Welcome! You are the first user. Please note that after registration, your role must be manually set to 'admin' in the database for secure initial setup.", 'info')

        # Use set_password from the User model (Bcrypt hashing)
        from werkzeug.security import generate_password_hash 
        new_user = User(username=username, email=email, role=user_role)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Your role is: Customer. Please log in and set up TOTP.", 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('totp_verified', None)
    logout_user()
    flash("Logged out successfully.", 'info')
    return redirect(url_for('login'))

# --- TOTP Routes ---

@app.route('/setup_totp', methods=['GET', 'POST'])
@login_required 
def setup_totp():
    # If a user hits this page, they should be logged in via the special login logic above.
    
    if current_user.totp_secret and current_user.totp_secret != '[Decryption/Tamper Error]':
        flash("TOTP is already set up. Please verify to continue.", 'warning')
        return redirect(url_for('verify_totp'))

    secret = pyotp.random_base32()
    current_user.totp_secret = secret 
    db.session.commit()

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="SecureBankWallet")

    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_totp.html', qr_code=qr_b64, secret=secret)

@app.route('/verify_totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    if session.get('totp_verified'):
        return redirect(url_for('dashboard_redirect'))
        
    if current_user.totp_secret == '[Decryption/Tamper Error]':
        flash("Error: Your saved TOTP secret appears tampered or corrupt. Please re-setup.", 'danger')
        current_user.encrypted_totp_secret = None
        db.session.commit()
        return redirect(url_for('setup_totp'))

    if request.method == 'POST':
        code = request.form['totp']
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code):
            session['totp_verified'] = True
            flash("TOTP verified successfully.", 'success')
            return redirect(url_for('dashboard_redirect'))
        else:
            flash("Invalid TOTP code. Please try again.", 'danger')
            return render_template('verify_totp.html')

    return render_template('verify_totp.html')

# --- Dashboard Routes ---

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    if not session.get('totp_verified'):
        flash("TOTP verification required.", 'danger')
        return redirect(url_for('verify_totp'))

    if current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'customer':
        return redirect(url_for('dashboard_customer'))
    else:
        flash("Unknown role.", 'danger')
        return redirect(url_for('login'))


def get_decrypted_transactions(blocks):
    decrypted_txns = []
    for db_block in blocks:
        try:
            block_data = json.loads(db_block.data)
            note = decrypt_data(block_data.get('encrypted_notes', ''))
            
            decrypted_txns.append({
                'user_id': block_data.get('user_id'),
                'amount': block_data.get('amount'),
                'recipient': block_data.get('recipient'),
                'note': note,
                'status': block_data.get('status'),
                'timestamp': db_block.timestamp.strftime('%Y-%m-%d %H:%M'),
                'block_hash': db_block.current_hash[:10] + '...'
            })
        except Exception as e:
            print(f"Error processing block {db_block.id}: {e}")
            decrypted_txns.append({'note': f'[DATA CORRUPT/ERROR IN BLOCK {db_block.index}]'})
    return decrypted_txns


@app.route('/dashboard/admin')
@login_required
@admin_required # Protected by the new decorator
def dashboard_admin():
    blocks = BlockModel.query.order_by(BlockModel.timestamp.desc()).all()
    decrypted_txns = get_decrypted_transactions(blocks)

    return render_template('dashboard_admin.html',
                            username=current_user.username,
                            transactions=decrypted_txns)

@app.route('/dashboard/customer')
@login_required
def dashboard_customer():
    # Blocked by dashboard_redirect if TOTP is not verified
    blocks = BlockModel.query.filter_by(user_id=current_user.id)\
                             .order_by(BlockModel.timestamp.desc()).all()
                             
    decrypted_txns = get_decrypted_transactions(blocks)

    return render_template('dashboard_customer.html',
                            username=current_user.username,
                            transactions=decrypted_txns)


# --- NEW ADMIN ACCOUNT PROVISIONING ROUTE ---

@app.route('/create_admin', methods=['GET', 'POST'])
@login_required
@admin_required
def create_admin_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", 'danger')
            return render_template('create_admin.html')

        new_user = User(username=username, email=email, role='admin')
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        flash(f"New Admin account created for {username}.", 'success')
        return redirect(url_for('dashboard_admin'))
        
    return render_template('create_admin.html')

# --- Transaction Route (Blockchain Integration) ---

@app.route('/submit_transaction', methods=['GET', 'POST'])
@login_required
def submit_transaction():
    form = TransactionForm()
    
    # 1. Check for TOTP Verification (Crucial Security Enhancement)
    if not session.get('totp_verified'):
        flash("TOTP verification required to submit a transaction.", 'danger')
        return redirect(url_for('verify_totp'))
        
    if form.validate_on_submit():
        # 2. Verify Fresh TOTP Code (Enforced security on sensitive action)
        totp_code = form.totp_code.data
        if not current_user.totp_secret:
             flash("TOTP not set up. Cannot submit transaction.", 'danger')
             return redirect(url_for('setup_totp'))
             
        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(totp_code):
            flash("Invalid TOTP code. Transaction rejected.", 'danger')
            return render_template('submit_transaction.html', form=form)

        # 3. Encrypt Transaction Notes (using AES-GCM)
        encrypted_notes = encrypt_data(form.notes.data)
        
        # 4. Prepare Transaction Data
        transaction_data = {
            'user_id': current_user.id,
            'amount': form.amount.data,
            'recipient': form.recipient.data,
            'encrypted_notes': encrypted_notes, 
            'status': form.status.data,
            'fee': 0.01 
        }
        
        # 5. Anomaly Check (Paper Mandate)
        if not anomaly_detection_check(transaction_data, current_user.id):
            return render_template('submit_transaction.html', form=form)

        # 6. MINE THE BLOCK (Blockchain Core Logic)
        new_block = blockchain.mine_new_transaction(transaction_data)
        
        # 7. Store the Mined Block in the Database (BlockModel)
        db_block = BlockModel(
            index=new_block.index,
            user_id=current_user.id,
            data=new_block.data, 
            timestamp=datetime.strptime(new_block.timestamp, '%Y-%m-%d %H:%M:%S'),
            nonce=new_block.nonce,
            current_hash=new_block.hash,
            previous_hash=new_block.previous_hash
        )
        
        db.session.add(db_block)
        db.session.commit()

        flash(f"Transaction recorded and mined into Block {new_block.index}. Hash: {new_block.hash[:10]}...", 'success')
        return redirect(url_for('dashboard_customer'))
        
    return render_template('submit_transaction.html', form=form)

# --- Final Execution ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        load_chain_from_db()
        
    app.run(debug=True)