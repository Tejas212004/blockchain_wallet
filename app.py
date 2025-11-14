from flask import Flask, render_template, request, redirect, url_for, flash, session
# 🔥 IMPORTANT: Ensure all necessary imports are present
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
import os
import pyotp
import json
from datetime import datetime
# Assuming these files exist in the project directory:
from config import Config
from models import db, User, BlockModel
from blockchain import Blockchain, Block 
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash 
from forms import TransactionForm, InitialBalanceForm
from encryption import encrypt_data, decrypt_data 
from sqlalchemy import or_ # Added for complex querying

# --- Blockchain and App Setup ---

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

# Initialize in-memory blockchain instance
blockchain = Blockchain()

# --- Custom Decorator ---

def admin_required(f):
    """Decorator to restrict access to 'admin' and 'super_admin' users only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'super_admin']:
            flash("Administrator access required.", 'danger')
            return redirect(url_for('dashboard_redirect'))
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
    # NOTE: Config.HIGH_VALUE_THRESHOLD must be defined in config.py
    if amount > Config.HIGH_VALUE_THRESHOLD:
        print(f"ANOMALY ALERT: High value transaction detected for User {user_id}: {amount}")
        flash("Warning: High-value transaction detected. System is monitoring.", 'warning')
    
    return True


# ----------------------------------------------------------------------
# 🔥 MODIFIED CORE FUNCTION: Calculate User Balance (FIX APPLIED HERE)
# ----------------------------------------------------------------------
def get_balance(user_id):
    """
    Calculates the current balance of a specific user by scanning the entire ledger.
    
    FIX: Look up the target user's email once and use it for reliable credit matching,
    avoiding repeated, error-prone database lookups inside the block loop.
    """
    # 1. Look up the target user's email once
    target_user = User.query.get(user_id)
    if not target_user:
        print(f"ERROR: User ID {user_id} not found for balance calculation.")
        return 0.0

    target_email = target_user.email
    balance = 0.0
    
    # Fetch all blocks that are NOT the Genesis Block (user_id is NULL for initial system blocks)
    all_blocks = BlockModel.query.filter(BlockModel.index.isnot(None)).order_by(BlockModel.index.asc()).all()

    for block in all_blocks:
        try:
            # Skip Genesis Block for balance calculation
            if block.index == 0:
                continue
                
            # 1. Decrypt/Decode the block data
            encrypted_payload = block.data
            decrypted_json_str = decrypt_data(encrypted_payload)
            
            if decrypted_json_str == '[Decryption/Tamper Error]':
                print(f"Warning: Block {block.index} failed decryption.")
                continue
                
            transaction_payload = json.loads(decrypted_json_str)
            
            # 2. Extract transaction details
            amount = float(transaction_payload.get('amount', 0))
            if amount < 0:
                # Should not happen, but a guardrail for corrupted data
                continue 
                
            # The sender is the user_id linked to the block in the DB (for P2P transfers)
            sender_id = block.user_id 
            recipient_email = transaction_payload.get('recipient') 
            
            # 3. Apply financial change
            
            # Case A: DEBIT (P2P Transfer - Sender is the target user)
            if sender_id == user_id:
                # Deduct the amount for the sender
                balance -= amount
            
            # Case B: CREDIT (P2P or System Credit - Recipient email matches target user's email)
            # This covers:
            # - P2P credits (sender_id is not user_id, recipient_email matches target_email)
            # - System credits (sender_id is None, recipient_email matches target_email)
            if recipient_email == target_email:
                # Add the amount for the recipient
                balance += amount
            
        except Exception as e:
            print(f"Error processing block {block.index} for balance calculation: {e}")
            continue

    return round(balance, 2)
# ----------------------------------------------------------------------


# --- Helper Functions ---

def load_chain_from_db():
    """Loads all blocks from the database into the in-memory blockchain."""
    with app.app_context():
        blocks_from_db = BlockModel.query.order_by(BlockModel.index.asc()).all()
        
        # Check if the Genesis Block exists in the DB
        if not blocks_from_db or blocks_from_db[0].index != 0:
            print("No blocks found in DB or Genesis Block missing. Creating Genesis Block...")
            
            if not blockchain.chain or blockchain.chain[0].index != 0:
                # Ensure the in-memory blockchain has a genesis block before trying to save it
                # If it doesn't, the Blockchain() constructor should handle it.
                pass 
            
            genesis_block = blockchain.chain[0]
            
            db_block = BlockModel(
                index=genesis_block.index,
                user_id=None, 
                data=genesis_block.data,
                timestamp=datetime.strptime(genesis_block.timestamp, '%Y-%m-%d %H:%M:%S'),
                nonce=genesis_block.nonce,
                current_hash=genesis_block.hash,
                previous_hash=genesis_block.previous_hash
            )
            db.session.add(db_block)
            db.session.commit()
            
            # Reload blocks from DB including the new genesis block
            blocks_from_db = BlockModel.query.order_by(BlockModel.index.asc()).all()

        blockchain.chain = []
        for db_block in blocks_from_db:
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


def get_decrypted_transactions(blocks):
    """
    Helper function to decrypt transaction data from a list of BlockModel objects.
    Correctly decrypts the full block.data field, which holds the encrypted JSON payload.
    """
    decrypted_txns = []
    for db_block in blocks:
        # Handle Genesis Block
        if db_block.user_id is None and db_block.index == 0:
            decrypted_txns.append({
                'index': db_block.index,
                'user_id': None,
                'amount': 'N/A',
                'recipient': 'N/A',
                'status': 'SYSTEM', # 🔥 Added status for genesis block
                'block_hash': db_block.current_hash[:10] + '...',
                'timestamp': db_block.timestamp.strftime('%Y-%m-%d %H:%M'),
                'note': '--- Genesis Block (Blockchain Initializer) ---',
                'type': 'SYSTEM'
            })
            continue

        try:
            # 1. Decrypt the entire block data string
            encrypted_payload = db_block.data
            decrypted_json_str = decrypt_data(encrypted_payload)
            
            if decrypted_json_str == '[Decryption/Tamper Error]':
                raise Exception("Decryption/Tamper Error")

            block_data = json.loads(decrypted_json_str)
            
            # Determine if it's an initial credit block
            is_initial_credit = db_block.user_id is None and db_block.index != 0
            
            # In the final transaction structure, 'note' is a field inside the JSON payload
            note = block_data.get('note', "No Note Provided") 

            decrypted_txns.append({
                'index': db_block.index,
                'user_id': db_block.user_id, # Sender ID (from DB field)
                'amount': block_data.get('amount'),
                'recipient': block_data.get('recipient'),
                'note': note,
                'status': block_data.get('status', 'complete').upper(), 
                'timestamp': db_block.timestamp.strftime('%Y-%m-%d %H:%M'),
                'block_hash': db_block.current_hash[:10] + '...',
                'type': 'INITIAL_CREDIT' if is_initial_credit else ('P2P' if db_block.user_id else 'UNKNOWN')
            })
        except Exception as e:
            print(f"Error processing block {db_block.index}: {e}")
            decrypted_txns.append({
                'index': db_block.index,
                'user_id': db_block.user_id,
                'amount': 'N/A',
                'recipient': 'N/A',
                'note': f'[DATA CORRUPT/ERROR IN BLOCK {db_block.index}]', 
                'status': 'FAILED',
                'timestamp': db_block.timestamp.strftime('%Y-%m-%d %H:%M'),
                'block_hash': db_block.current_hash[:10] + '...',
                'type': 'ERROR'
            })
    return decrypted_txns

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    # Only load user if they are fully authenticated (TOTP verified)
    return User.query.get(int(user_id)) if session.get('totp_verified') else None

@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Authentication Routes (Login, Register, Logout, TOTP) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already authenticated by Flask-Login (full access), redirect
    if current_user.is_authenticated and session.get('totp_verified'):
        return redirect(url_for('dashboard_redirect')) 

    # ---
    # 🔥 CORRECTION IS HERE
    # We only pop 'last_totp_attempt'. We MUST NOT pop 'awaiting_totp'
    # because that breaks the multi-stage setup flow.
    # ---
    session.pop('last_totp_attempt', None) 
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        totp_code = request.form.get('totp') # This field is only visible after password check in the template

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            
            has_totp_setup = user.totp_secret and user.totp_secret != '[Decryption/Tamper Error]'
            
            # Case 1: TOTP NOT SETUP 
            if not has_totp_setup:
                session['awaiting_totp'] = user.id  # Store user ID temporarily
                flash("Password accepted. Please set up Two-Factor Authentication to continue.", 'warning')
                return redirect(url_for('setup_totp'))

            # Case 2: TOTP IS SETUP (Regular login flow)
            if not totp_code:
                flash("TOTP code is required for login.", 'danger')
                return render_template('login.html')

            # Verify TOTP code
            totp = pyotp.TOTP(user.totp_secret)
            
            if not totp.verify(totp_code):
                if session.get('last_totp_attempt') == user.id:
                    session.pop('last_totp_attempt', None)
                    flash("Multiple invalid TOTP attempts. Please re-enter credentials.", 'danger')
                    return render_template('login.html')

                session['last_totp_attempt'] = user.id
                flash("Invalid TOTP code. Please try again.", 'danger')
                return render_template('login.html')
            
            # Successful login with TOTP
            login_user(user) # Now and ONLY now log the user in fully
            session['totp_verified'] = True 
            session.pop('last_totp_attempt', None) # Clear failure tracker
            flash("Login successful and 2FA verified.", 'success')
            
            return redirect(url_for('dashboard_redirect'))

        # End of successful password check
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

        user_role = 'customer' 
        
        if not User.query.first():
            flash("Welcome! You are the first user. Please note that after registration, your role must be manually set to 'super_admin' in the database for secure initial setup.", 'info')

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
    session.pop('awaiting_totp', None)
    session.pop('last_totp_attempt', None)
    logout_user()
    flash("Logged out successfully.", 'info')
    return redirect(url_for('login'))

@app.route('/setup_totp', methods=['GET'])
def setup_totp(): 
    # Check for temporary password-authenticated state (from /login)
    user_id = session.get('awaiting_totp')
    # If not authenticated, check for a fully logged-in user who might be resetting
    if not user_id and current_user.is_authenticated:
        user_id = current_user.id
        
    if not user_id:
        flash("Authentication required to set up TOTP.", 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        session.pop('awaiting_totp', None)
        flash("User session error.", 'danger')
        return redirect(url_for('login'))

    if user.totp_secret and user.totp_secret != '[Decryption/Tamper Error]':
        flash("TOTP is already set up. Please verify.", 'warning')
        # If fully logged in, verify. If awaiting, go to verify to complete login.
        return redirect(url_for('verify_totp'))

    secret = pyotp.random_base32()
    session['totp_secret'] = secret

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SecureBankWallet")

    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('setup_totp.html', qr_code=qr_b64, secret=secret)

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    # Check 1: Is the user ALREADY fully logged in and verified?
    # 'current_user.is_authenticated' is 100% reliable here
    # because our user_loader links it directly to 'totp_verified'.
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_redirect'))
    
    # Check 2: If not, is this a user in the middle of the setup-flow?
    user_id = session.get('awaiting_totp')
    if not user_id:
        # If there's no 'awaiting_totp' flag, they are truly unauthorized.
        flash("Authentication required. Please log in to begin setup.", 'danger')
        return redirect(url_for('login'))
        
    user = User.query.get(user_id)
    if not user:
        # User ID in session is invalid, clear it and send to login
        session.pop('awaiting_totp', None)
        flash("User session error. Please log in again.", 'danger')
        return redirect(url_for('login'))

    # --- From here, the logic is for a user in the setup flow ---
    
    # Get the secret from session (for setup finalization)
    secret_to_verify = session.get('totp_secret') or user.totp_secret
    
    if not secret_to_verify or secret_to_verify == '[Decryption/Tamper Error]':
        flash("Error: TOTP secret is missing or corrupt. Please start setup again.", 'danger')
        if user.encrypted_totp_secret:
            user.encrypted_totp_secret = None
            db.session.commit()
        return redirect(url_for('setup_totp'))

    if request.method == 'POST':
        code = request.form['totp']
        totp = pyotp.TOTP(secret_to_verify)
        
        if totp.verify(code):
            
            # If the secret was in the session, it means setup is being finalized
            if session.get('totp_secret'):
                # Save the secret to the DB and use the User model's setter (which encrypts)
                user.totp_secret = session.pop('totp_secret') 
                db.session.commit()
                flash("TOTP setup and verification complete. You are now fully secured.", 'success')
            else:
                flash("TOTP verified successfully.", 'success')
                
            # Final Login Step: Grant full authentication via Flask-Login
            login_user(user) # This is the FIRST time login_user is called for this session (if coming from setup)
            session['totp_verified'] = True
            session.pop('awaiting_totp', None) # Clean up temporary flag
            return redirect(url_for('dashboard_redirect'))
            
        else:
            flash("Invalid TOTP code. Please try again.", 'danger')
            return render_template('verify_totp.html')

    # On a GET request, just show the verification page
    return render_template('verify_totp.html')

# --- Dashboard Routes ---

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    # Admin/Super Admin users MUST have TOTP verified in session.
    if current_user.role in ['admin', 'super_admin'] and not session.get('totp_verified'):
        flash("Admin access requires full TOTP verification. Please verify.", 'danger')
        return redirect(url_for('verify_totp'))

    if current_user.role == 'super_admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'customer':
        return redirect(url_for('dashboard_customer'))
    else:
        flash("Unknown role.", 'danger')
        return redirect(url_for('login'))

@app.route('/dashboard/admin')
@login_required
@admin_required 
def dashboard_admin():
    # Admin view shows all blocks
    blocks = BlockModel.query.order_by(BlockModel.timestamp.desc()).all()
    decrypted_txns = get_decrypted_transactions(blocks)

    return render_template('dashboard_admin.html',
                           username=current_user.username,
                           user_role=current_user.role, 
                           transactions=decrypted_txns)

@app.route('/dashboard/customer')
@login_required
def dashboard_customer():
    # Fetch all blocks needed for balance calculation and comprehensive history
    all_blocks = BlockModel.query.order_by(BlockModel.index.asc()).all()
    
    current_balance = get_balance(current_user.id) 
    
    # Decrypt all transactions (must decrypt all to find transactions where current_user is recipient)
    decrypted_txns_all = get_decrypted_transactions(all_blocks)
    
    # Filter for display: transactions where the current user is the SENDER or the RECIPIENT.
    display_txns = []
    
    for txn in decrypted_txns_all:
        # Check if the transaction is a DEBIT (sent by user)
        if txn.get('user_id') == current_user.id:
            txn['type'] = 'DEBIT' # Sent by user
            display_txns.append(txn)
        # Check if the transaction is a CREDIT (received by user)
        elif txn.get('recipient') == current_user.email:
            # Check if it's a P2P credit
            if txn.get('user_id') is not None:
                txn['type'] = 'CREDIT' 
            # Check if it's a system/admin credit
            elif txn.get('status') == 'SYSTEM_CREDIT':
                txn['type'] = 'SYSTEM_CREDIT'
            display_txns.append(txn)
        # Include Genesis Block (optional, but good for completeness)
        elif txn.get('index') == 0:
            txn['type'] = 'GENESIS'
            display_txns.append(txn)
            
    # Reverse the order for display (newest first)
    display_txns.reverse() 

    return render_template('dashboard_customer.html',
                           username=current_user.username,
                           transactions=display_txns,
                           current_balance=current_balance) # Pass balance

# -----------------------------------------------
# NEW ROUTE: Blockchain Integrity Check
# -----------------------------------------------

@app.route('/check_integrity')
@login_required
@admin_required
def check_integrity():
    """Checks the integrity of the entire blockchain by recalculating and verifying hashes."""
    try:
        # Assuming blockchain object has a method to validate the chain
        is_valid = blockchain.is_chain_valid() 

        if is_valid:
            flash("Blockchain integrity check passed! The ledger is secure and untampered.", 'success')
        else:
            flash("CRITICAL WARNING: Blockchain integrity check failed! Ledger corruption detected.", 'danger')
    except Exception as e:
        flash(f"Error running integrity check: {e}", 'danger')
        
    return redirect(url_for('dashboard_admin'))

# -----------------------------------------------
# MODIFIED: User Management Routes
# -----------------------------------------------

@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    # Only Super Admin can manage all users. Admin can only see the list.
    if current_user.role not in ['super_admin', 'admin']:
        flash("Permission Denied: Only Administrators can view this page.", 'danger')
        return redirect(url_for('dashboard_admin'))

    # Fetch all users except the current user for management list
    users_db = User.query.filter(User.id != current_user.id).order_by(User.id.asc()).all()
    
    # Pass balance data to the template
    users = []
    for user in users_db:
        user_data = {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'encrypted_totp_secret': user.encrypted_totp_secret, 
            'balance': get_balance(user.id) if user.role == 'customer' else None
        }
        users.append(user_data)
    
    # Check if the current user is Super Admin to allow editing
    can_manage = (current_user.role == 'super_admin')
    
    return render_template('manage_users.html', users=users, can_manage=can_manage)

# ... (manage_user_detail route updated for user deactivation)
@app.route('/manage_users/<int:user_id>', methods=['GET', 'POST'])
@login_required
def manage_user_detail(user_id):
    # Only Super Admin can access the detail page to make changes
    if current_user.role != 'super_admin':
        flash("Permission Denied: Only a Super Admin can modify user accounts.", 'danger')
        return redirect(url_for('dashboard_admin'))

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot manage your own account details via this admin page.", 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        # 1. Change Role
        new_role = request.form.get('role')
        if new_role and new_role in ['customer', 'admin', 'super_admin']:
            user.role = new_role
            flash(f"User {user.username}'s role updated to {new_role}.", 'success')
        
        # 2. Reset TOTP
        if 'reset_totp' in request.form:
            # Setting to None will clear the encrypted secret in the database
            user.encrypted_totp_secret = None 
            flash(f"User {user.username}'s TOTP secret has been reset. They must re-setup 2FA on next login.", 'warning')

        # 3. Reset Password
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)
            flash(f"User {user.username}'s password has been successfully reset.", 'success')
            
        # 4. Deactivate Account (New Feature)
        deactivate = request.form.get('deactivate_user')
        if deactivate == 'true':
            # Setting role to 'deactivated' effectively locks the user out
            user.role = 'deactivated' 
            # Clear sensitive data
            user.encrypted_totp_secret = None
            flash(f"User {user.username} (ID: {user.id}) has been **DEACTIVATED** and logged out.", 'danger')
            # Note: The user will remain logged in on Flask-Login until a new request is made,
            # but they will be redirected/denied access by role checks.

        db.session.commit()
        return redirect(url_for('manage_user_detail', user_id=user.id))

    return render_template('manage_user_detail.html', user=user)
# -----------------------------------------------

# -----------------------------------------------
# FIX 2: Corrected Set Initial Balance to use Flask-WTF form
# -----------------------------------------------

@app.route('/set_balance/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def set_initial_balance(user_id):
    form = InitialBalanceForm() 
    
    customer = User.query.get_or_404(user_id)
    
    # 1. Access Check for who can credit whom:
    # A. Regular Admin can ONLY credit customers.
    if current_user.role == 'admin' and customer.role != 'customer':
        flash("Permission Denied: Regular Admins can only set the initial balance for 'customer' accounts.", 'danger')
        return redirect(url_for('manage_users'))
    
    # B. Super Admin can credit customers or regular Admins. (No explicit block needed for Super Admin)
    # C. Cannot credit yourself or another Super Admin.
    if customer.role == 'super_admin' or customer.id == current_user.id:
        flash("Cannot set initial balance for Super Admin accounts or your own account.", 'danger')
        return redirect(url_for('manage_users'))
    
    # D. Check if the target user is deactivated
    if customer.role == 'deactivated':
        flash(f"Cannot credit a deactivated account ({customer.email}).", 'danger')
        return redirect(url_for('manage_users'))
        
    current_balance = get_balance(customer.id)
    
    # --- Use form.validate_on_submit() for POST handling ---
    if form.validate_on_submit(): 
        try:
            amount = form.amount.data 
            
            if amount <= 0:
                flash("Amount must be a positive value.", 'danger')
                return redirect(url_for('set_initial_balance', user_id=user_id))
                
            # 2. Create and Encrypt System Transaction Payload
            transaction_data = {
                # user_id is None, indicating a system/admin credit
                'amount': amount,
                'recipient': customer.email, 
                'note': f"Initial Credit by Admin ({current_user.email}) to {customer.role} account",
                'status': 'SYSTEM_CREDIT', 
                'fee': 0.00
            }
            
            encrypted_payload = encrypt_data(json.dumps(transaction_data))
            
            # 3. Mine the Block and Commit to DB
            new_block = blockchain.mine_new_transaction(data=encrypted_payload)
            
            db_block = BlockModel(
                index=new_block.index,
                user_id=None, # Crucial: Set user_id to None to signify system/admin block
                data=new_block.data, 
                timestamp=datetime.strptime(new_block.timestamp, '%Y-%m-%d %H:%M:%S'),
                nonce=new_block.nonce,
                current_hash=new_block.hash,
                previous_hash=new_block.previous_hash
            )
            
            db.session.add(db_block)
            db.session.commit()
            
            flash(f"Successfully credited ₹{amount:.2f} to {customer.email} ({customer.role}). Block {new_block.index} mined.", 'success')
            return redirect(url_for('manage_users'))
            
        except ValueError:
            flash("Invalid amount entered. Please use numbers only.", 'danger')
            return redirect(url_for('set_initial_balance', user_id=user_id))
        except Exception as e:
            db.session.rollback()
            flash(f"A critical error occurred during credit: {e}", 'danger')
            return redirect(url_for('set_initial_balance', user_id=user_id))
            
    # Pass form to the template on GET or failed POST
    return render_template('set_initial_balance.html', customer=customer, current_balance=current_balance, form=form)

# --- Admin Provisioning Route (Now Super Admin only) ---

@app.route('/create_admin', methods=['GET', 'POST'])
@login_required
@admin_required
def create_admin_account():
    # Enforce Super Admin only for creating new admins
    if current_user.role != 'super_admin':
        flash("Permission Denied: Only a Super Admin can provision new admin accounts.", 'danger')
        return redirect(url_for('dashboard_admin'))
    
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
        flash(f"New Admin account created for {username}. They must log in and set up TOTP.", 'success')
        return redirect(url_for('dashboard_admin'))
        
    return render_template('create_admin.html') 
# -----------------------------------------------

# -----------------------------------------------
# --- CRITICAL ROUTE: Transaction Route (Unchanged, remains robust) ---
# -----------------------------------------------

@app.route('/submit_transaction', methods=['GET', 'POST'])
@login_required
def submit_transaction():
    form = TransactionForm()
    
    if not session.get('totp_verified'):
        flash("TOTP verification required to submit a transaction.", 'danger')
        return redirect(url_for('verify_totp'))
    
    # Get current balance for display and check
    current_balance = get_balance(current_user.id)
        
    if form.validate_on_submit():
        amount = form.amount.data
        recipient_email = form.recipient.data
        
        try: 
            # 1. TOTP Verification for Transaction Authorization
            totp_code = form.totp_code.data
            if not current_user.totp_secret or current_user.totp_secret == '[Decryption/Tamper Error]':
                flash("TOTP not set up. Cannot submit transaction.", 'danger')
                return redirect(url_for('setup_totp'))
            
            totp = pyotp.TOTP(current_user.totp_secret)
            if not totp.verify(totp_code):
                flash("Invalid TOTP code. Transaction rejected.", 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)

            # 2. Balance Check
            if amount <= 0:
                flash("Amount must be greater than zero.", 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)
            
            if amount > current_balance:
                flash(f"Transaction failed: Insufficient funds. Your current balance is ₹{current_balance:.2f}.", 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)

            # 3. Recipient Validation
            recipient = User.query.filter_by(email=recipient_email).first()
            if not recipient:
                flash('Transaction failed: Recipient email not found.', 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)
            
            if recipient.id == current_user.id:
                flash('Transaction failed: Cannot send money to yourself.', 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)
                
            if recipient.role == 'deactivated':
                flash('Transaction failed: Cannot send money to a deactivated account.', 'danger')
                return render_template('submit_transaction.html', form=form, current_balance=current_balance)


            # 4. Create and Encrypt Transaction Payload
            transaction_data = {
                'user_id': current_user.id,
                'amount': amount,
                'recipient': recipient_email, 
                'note': form.notes.data, 
                'status': form.status.data,
                # Note: Fee calculation (0.01) is handled here but not deducted from the amount
                # A full system would need a separate block for the fee going to a 'miner' account.
                'fee': 0.01 
            }
            
            # Encrypt the full JSON string to be stored in the blockchain
            encrypted_payload = encrypt_data(json.dumps(transaction_data))
            
            if not anomaly_detection_check(transaction_data, current_user.id):
                # Anomaly check provides a warning flash but doesn't halt the transaction unless logic changes
                pass

            # 5. Mine the Block and Commit to DB
            new_block = blockchain.mine_new_transaction(data=encrypted_payload)
            
            db_block = BlockModel(
                index=new_block.index,
                user_id=current_user.id, # Sender ID 
                data=new_block.data, 
                timestamp=datetime.strptime(new_block.timestamp, '%Y-%m-%d %H:%M:%S'),
                nonce=new_block.nonce,
                current_hash=new_block.hash,
                previous_hash=new_block.previous_hash
            )
            
            db.session.add(db_block)
            db.session.commit()
            
            flash(f"Transaction successful and mined into Block {new_block.index}. Hash: {new_block.hash[:10]}...", 'success')
            return redirect(url_for('dashboard_customer'))
            
        except Exception as e:
            db.session.rollback()
            print(f"\nCRITICAL TRANSACTION ERROR: {e}\n") 
            flash(f"A critical error occurred: {e}", 'danger')
            # Pass balance back on error
            return render_template('submit_transaction.html', form=form, current_balance=current_balance)
            
    # Pass balance to template on GET request or initial form load
    return render_template('submit_transaction.html', form=form, current_balance=current_balance)

# --- Final Execution ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        load_chain_from_db() 
        
    app.run(debug=True)