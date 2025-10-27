from flask import Flask, render_template, request, redirect, url_for, flash, session
# 🔥 IMPORTANT: Ensure all necessary imports are present
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
import os
import pyotp
import json
from datetime import datetime
from config import Config
from models import db, User, BlockModel
from blockchain import Blockchain, Block 
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash 
from forms import TransactionForm
from encryption import encrypt_data, decrypt_data 

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
            blocks_from_db.append(db_block)

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

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    # Only load user if they are fully authenticated (TOTP verified)
    # The session flag 'awaiting_totp' handles pre-2FA state
    return User.query.get(int(user_id)) if session.get('totp_verified') else None

@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Authentication Routes (NO CHANGES HERE) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already authenticated by Flask-Login (full access), redirect
    if current_user.is_authenticated and session.get('totp_verified'):
        return redirect(url_for('dashboard_redirect')) 

    # Clean up temporary flags if the user is revisiting the login page
    session.pop('awaiting_totp', None)
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
    # ... (Register route logic is unchanged) ...
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

# --- TOTP Routes (Setup, Verify) (NO CHANGES HERE) ---

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
    # Identify the user (either awaiting setup OR already fully logged in)
    user_id = session.get('awaiting_totp') or (current_user.id if current_user.is_authenticated else None)

    if not user_id:
        flash("Authentication required for verification.", 'danger')
        return redirect(url_for('login'))
        
    user = User.query.get(user_id)
    if not user:
        session.pop('awaiting_totp', None)
        flash("User session error.", 'danger')
        return redirect(url_for('login'))

    # If already verified, go to dashboard
    if user.is_authenticated and session.get('totp_verified'):
        return redirect(url_for('dashboard_redirect'))
        
    # Get the secret from session (for setup finalization) or user object (for re-verification)
    secret_to_verify = session.get('totp_secret') or user.totp_secret
    
    if not secret_to_verify or secret_to_verify == '[Decryption/Tamper Error]':
        flash("Error: TOTP secret is missing or corrupt. Please start setup again.", 'danger')
        # Cleanup a potentially corrupt secret and force re-setup
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

    return render_template('verify_totp.html')

# --- Dashboard Routes (Unchanged) ---

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

def get_decrypted_transactions(blocks):
    # ... (Helper function logic is unchanged) ...
    decrypted_txns = []
    for db_block in blocks:
        try:
            block_data = json.loads(db_block.data)
            encrypted_note = block_data.get('encrypted_notes', '')
            note = decrypt_data(encrypted_note) if encrypted_note else "No Note" 
            
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
@admin_required 
def dashboard_admin():
    blocks = BlockModel.query.order_by(BlockModel.timestamp.desc()).all()
    decrypted_txns = get_decrypted_transactions(blocks)

    return render_template('dashboard_admin.html',
                            username=current_user.username,
                            user_role=current_user.role, 
                            transactions=decrypted_txns)

@app.route('/dashboard/customer')
@login_required
def dashboard_customer():
    blocks = BlockModel.query.filter_by(user_id=current_user.id)\
                             .order_by(BlockModel.timestamp.desc()).all()
                             
    decrypted_txns = get_decrypted_transactions(blocks)

    return render_template('dashboard_customer.html',
                            username=current_user.username,
                            transactions=decrypted_txns)


# -----------------------------------------------
# --- NEW: User Management Routes ---
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
    users = User.query.filter(User.id != current_user.id).order_by(User.id.asc()).all()
    
    # Check if the current user is Super Admin to allow editing
    can_manage = (current_user.role == 'super_admin')
    
    return render_template('manage_users.html', users=users, can_manage=can_manage)

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

        # 3. Reset Password (Included from your previous code)
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)
            flash(f"User {user.username}'s password has been successfully reset.", 'success')

        db.session.commit()
        return redirect(url_for('manage_user_detail', user_id=user.id))

    return render_template('manage_user_detail.html', user=user)

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

# --- Transaction Route (Unchanged) ---

@app.route('/submit_transaction', methods=['GET', 'POST'])
@login_required
def submit_transaction():
    # ... (Logic is unchanged) ...
    form = TransactionForm()
    
    if not session.get('totp_verified'):
        flash("TOTP verification required to submit a transaction.", 'danger')
        return redirect(url_for('verify_totp'))
        
    if form.validate_on_submit():
        try: 
            totp_code = form.totp_code.data
            if not current_user.totp_secret:
                 flash("TOTP not set up. Cannot submit transaction.", 'danger')
                 return redirect(url_for('setup_totp'))
                 
            totp = pyotp.TOTP(current_user.totp_secret)
            if not totp.verify(totp_code):
                print(f"DEBUG: TOTP verification failed for code: {totp_code}") 
                flash("Invalid TOTP code. Transaction rejected.", 'danger')
                return render_template('submit_transaction.html', form=form)

            print("DEBUG: TOTP verification successful. Proceeding to mining.") 

            encrypted_notes = encrypt_data(form.notes.data) 
            
            transaction_data = {
                'user_id': current_user.id,
                'amount': form.amount.data,
                'recipient': form.recipient.data,
                'encrypted_notes': encrypted_notes, 
                'status': form.status.data,
                'fee': 0.01 
            }
            
            if not anomaly_detection_check(transaction_data, current_user.id):
                print("DEBUG: Anomaly check returned False. Transaction halted.") 
                return render_template('submit_transaction.html', form=form)

            print("DEBUG: Anomaly check passed. Mining block...") 

            new_block = blockchain.mine_new_transaction(transaction_data)
            
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
            print(f"DEBUG: Block {new_block.index} successfully mined and committed.") 

            flash(f"Transaction recorded and mined into Block {new_block.index}. Hash: {new_block.hash[:10]}...", 'success')
            return redirect(url_for('dashboard_customer'))
            
        except Exception as e:
            db.session.rollback()
            print(f"\nCRITICAL TRANSACTION ERROR: {e}\n") 
            flash(f"A critical error occurred: {e}", 'danger')
            return render_template('submit_transaction.html', form=form)
            
    return render_template('submit_transaction.html', form=form)

# --- Final Execution ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        load_chain_from_db() 
        
    app.run(debug=True)