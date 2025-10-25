from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import os
import pyotp
from models import db, User, Transaction
from forms import TransactionForm
import qrcode
import io
import base64


# Load environment
load_dotenv()
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    raise ValueError("ENCRYPTION_KEY not found in environment variables.")
fernet = Fernet(encryption_key.encode())

# Flask setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet.db'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback_secret")
db.init_app(app)
migrate = Migrate(app, db)

# Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        totp_code = request.form.get('totp')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)

            if not user.totp_secret:
                flash("Please set up TOTP to continue.")
                return redirect(url_for('setup_totp'))

            if not totp_code:
                logout_user()
                flash("TOTP code is required.")
                return render_template('login.html')

            totp = pyotp.TOTP(user.totp_secret)
            if not totp.verify(totp_code):
                logout_user()
                flash("Invalid TOTP code.")
                return render_template('login.html')

            # All checks passed
            session['totp_verified'] = True
            return redirect(url_for('dashboard_redirect'))

        flash("Invalid email or password.")
        return render_template('login.html')

    return render_template('login.html')
# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already registered.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

# Dashboard

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    if not session.get('totp_verified'):
        flash("TOTP verification required.")
        return redirect(url_for('verify_totp'))

    if current_user.role == 'admin':
        return redirect(url_for('dashboard_admin'))
    elif current_user.role == 'customer':
        return redirect(url_for('dashboard_customer'))
    else:
        flash("Unknown role.")
        return redirect(url_for('login'))

@app.route('/dashboard/admin')
@login_required
def dashboard_admin():
    if not session.get('totp_verified'):
        flash("TOTP verification required.")
        return redirect(url_for('verify_totp'))

    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('dashboard_customer'))

    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    decrypted_txns = []

    for txn in transactions:
        try:
            note = fernet.decrypt(txn.encrypted_notes.encode()).decode() if txn.encrypted_notes else ''
        except Exception as e:
            print(f"Decryption failed for txn {txn.id}: {e}")
            note = '[Decryption error]'

        decrypted_txns.append({
            'user_id': txn.user_id,
            'amount': txn.amount,
            'recipient': txn.recipient,
            'note': note,
            'status': txn.status,
            'timestamp': txn.timestamp.strftime('%Y-%m-%d %H:%M')
        })

    return render_template('dashboard_admin.html',
                           username=current_user.username,
                           transactions=decrypted_txns)

@app.route('/dashboard/customer')
@login_required
def dashboard_customer():
    if not session.get('totp_verified'):
        flash("TOTP verification required.")
        return redirect(url_for('verify_totp'))

    if current_user.role != 'customer':
        flash("Unauthorized access.")
        return redirect(url_for('dashboard_admin'))

    transactions = Transaction.query.filter_by(user_id=current_user.id)\
                                    .order_by(Transaction.timestamp.desc()).all()
    decrypted_txns = []

    for txn in transactions:
        try:
            note = fernet.decrypt(txn.encrypted_notes.encode()).decode() if txn.encrypted_notes else ''
        except Exception as e:
            print(f"Decryption failed for txn {txn.id}: {e}")
            note = '[Decryption error]'

        decrypted_txns.append({
            'amount': txn.amount,
            'recipient': txn.recipient,
            'note': note,
            'status': txn.status,
            'timestamp': txn.timestamp.strftime('%Y-%m-%d %H:%M')
        })

    return render_template('dashboard_customer.html',
                           username=current_user.username,
                           transactions=decrypted_txns)

# Submit transaction
@app.route('/submit_transaction', methods=['GET', 'POST'])
@login_required
def submit_transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        encrypted_notes = fernet.encrypt(form.notes.data.encode()).decode()
        transaction = Transaction(
            user_id=current_user.id,
            amount=form.amount.data,
            recipient=form.recipient.data,
            encrypted_notes=encrypted_notes,
            status=form.status.data
        )
        db.session.add(transaction)
        db.session.commit()
        flash("Transaction submitted.")
        return redirect(url_for('dashboard'))
    return render_template('submit_transaction.html', form=form)

# TOTP setup
@app.route('/setup_totp', methods=['GET', 'POST'])
@login_required
def setup_totp():
    if current_user.totp_secret:
        return redirect(url_for('verify_totp'))

    # Generate new TOTP secret
    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.session.commit()

    # Create provisioning URI
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="TejasWallet")

    # Generate QR code and convert to base64
    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_totp.html', qr_code=qr_b64, secret=secret)

# TOTP verification
@app.route('/verify_totp', methods=['GET', 'POST'])
@login_required
def verify_totp():
    if request.method == 'POST':
        code = request.form['totp']
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code):
            session['totp_verified'] = True
            flash("TOTP verified successfully.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid TOTP code. Please try again.")
            return render_template('verify_totp.html')

    return render_template('verify_totp.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)