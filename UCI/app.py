from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import qrcode
from bit import PrivateKeyTestnet as Key  # Use PrivateKeyTestnet for testnet
from io import BytesIO
import cv2
import numpy as np
import json 
import sqlite3
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Load configuration from config.json
with open('config.json') as config_file:
    config = json.load(config_file)

# Retrieve Bitcoin address and private key
btc_address = config.get('btc_address')
btc_private_key = config.get('btc_private_key')

# Optionally, you can handle missing keys
if btc_address is None or btc_private_key is None:
    raise ValueError("Bitcoin address or private key not found in config.json")

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Load configuration from config.json
def load_config():
    with open('config.json') as config_file:
        return json.load(config_file)

# Save configuration to config.json
def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)
        
def init_db():
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            receiver_address TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL
        )
    ''')
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()


def log_transaction(receiver_address, amount, status):
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO transactions (receiver_address, amount, status)
        VALUES (?, ?, ?)
    ''', (receiver_address, amount, status))
    conn.commit()
    conn.close()
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = sqlite3.connect('transactions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['username'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
        
        conn.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user already exists
        conn = sqlite3.connect('transactions.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert new user into the database
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/me', methods=['GET', 'POST'])
def me():
    config = load_config()

    if request.method == 'POST':
        # Get user information from the form
        name = request.form.get('name')
        email = request.form.get('email')
        btc_address = request.form.get('btc_address')
        btc_private_key = request.form.get('btc_private_key')

        # Update config with user information
        config['user']['name'] = name
        config['user']['email'] = email
        config['btc_address'] = btc_address
        config['btc_private_key'] = btc_private_key

        # Save the updated configuration
        save_config(config)

        flash('User information saved successfully!', 'success')
        return redirect(url_for('me'))

    user_info = config['user']

    # Check if balance is in config, otherwise default to 0.0
    if 'balance' in user_info:
        current_balance = user_info['balance']
    else:
        current_balance = 0.0  # Default value

    user_info['balance'] = current_balance  # Ensure balance is in user_info

    return render_template('me.html', user_info=user_info)


def is_valid_btc_address(address):
    """ Simple regex for validating Bitcoin addresses (including Bech32 for testnet) """
    if address is None:  # Check if address is None
        return False

    # Regex for legacy (P2PKH and P2SH) addresses
    btc_address_regex = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'
    # Regex for Bech32 (SegWit) addresses
    bech32_regex = r'^tb1[a-z0-9]{39,59}$'

    return re.match(btc_address_regex, address) is not None or re.match(bech32_regex, address) is not None


@app.route('/scan_qr')
def scan_qr():
    """ Handles QR code scanning and returns the detected address. """
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return jsonify({'status': 'error', 'message': 'Could not open camera. Ensure it is connected and not in use.'}), 500

    detector = cv2.QRCodeDetector()
    
    while True:
        success, frame = cap.read()
        if not success:
            break

        qr_data, points, _ = detector.detectAndDecode(frame)
        if qr_data and is_valid_btc_address(qr_data):
            cap.release()
            cv2.destroyAllWindows()
            return jsonify({'status': 'success', 'address': qr_data})

    cap.release()
    cv2.destroyAllWindows()
    return jsonify({'status': 'error', 'message': 'No valid QR code found.'}), 404


@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

def generate_frames():
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return  # Handle error appropriately

    detector = cv2.QRCodeDetector()  # Initialize QR code detector
    
    while True:
        success, frame = cap.read()
        if not success:
            break

        # QR Code detection
        qr_data, points, _ = detector.detectAndDecode(frame)
        
        # If a valid QR code is detected, you can handle it here
        if qr_data:
            print(f"Detected QR Code: {qr_data}")  # Log or process the detected data
            # You can break the loop or handle the detected data as needed

        # Encode frame to JPEG for streaming
        ret, buffer = cv2.imencode('.jpg', frame)
        if not ret:
            break
        frame = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()


@app.route('/', methods=['GET', 'POST'])
def index():
    # Check if the user is logged in
    if 'username' not in session:
        flash('Please log in to continue.', 'error')
        return redirect(url_for('login'))
    
    
    # Fetch the last 10 transactions
    try:
        with sqlite3.connect('transactions.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT receiver_address, amount, timestamp, status FROM transactions ORDER BY timestamp DESC LIMIT 10')
            last_transactions = cursor.fetchall()
    except sqlite3.DatabaseError as e:
        flash(f'Error fetching recent transactions: {str(e)}', 'error')
        last_transactions = []
    
    if request.method == 'POST':
        receiver_address = None
    
        if 'image' in request.files:  # Handling QR code upload
            image_file = request.files['image']
            if image_file.filename == '':
                flash('No QR code image uploaded.', 'error')
                return redirect(url_for('index'))

            try:
                image_stream = np.frombuffer(image_file.read(), np.uint8)
                img = cv2.imdecode(image_stream, cv2.IMREAD_COLOR)
                detector = cv2.QRCodeDetector()
                qr_data, points, _ = detector.detectAndDecode(img)

                if not qr_data or not is_valid_btc_address(qr_data):
                    flash('Invalid or no Bitcoin address found in QR code.', 'error')
                    log_transaction(receiver_address, request.form.get('amount'), 'Invalid QR code')
                    return redirect(url_for('index'))

                receiver_address = qr_data
                flash(f'Bitcoin address detected: {receiver_address}', 'success')

            except Exception as e:
                flash(f'Error processing QR code: {str(e)}', 'error')
                log_transaction(receiver_address, request.form.get('amount'), f'Error processing QR: {str(e)}')
                return redirect(url_for('index'))

        else:  # Handling manual input
            receiver_address = request.form.get('receiver_address')
            if not receiver_address:
                flash('No Receiver Address.', 'error')
                log_transaction(receiver_address, request.form.get('amount'), 'No Receiver Address')
                return redirect(url_for('index'))

            if not is_valid_btc_address(receiver_address):
                flash('Invalid Bitcoin address.', 'error')
                log_transaction(receiver_address, request.form.get('amount'), 'Invalid Bitcoin address')
                return redirect(url_for('index'))

        try:
            amount = float(request.form.get('amount'))
            if amount <= 0:
                flash('Amount must be greater than zero.', 'error')
                log_transaction(receiver_address, amount, 'Amount must be greater than zero')
                return redirect(url_for('index'))

            key = Key()  # Generate a new testnet private key for each transaction

            balance = key.get_balance('btc')
            balance = float(balance)
            if amount > balance:
                flash('Insufficient funds for transaction.', 'error')
                log_transaction(receiver_address, amount, 'Insufficient funds')
                return redirect(url_for('index'))

            tx_hash = key.send([(receiver_address, amount, 'btc')])
            flash(f'Successfully sent {amount} BTC to {receiver_address}. Transaction hash: {tx_hash}', 'success')
            log_transaction(receiver_address, amount, 'Successful')

        except ValueError:
            flash('Invalid amount entered.', 'error')
            log_transaction(receiver_address, request.form.get('amount'), 'Invalid amount entered')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            log_transaction(receiver_address, request.form.get('amount'), f'Error: {str(e)}')

        return redirect(url_for('index'))

    return render_template('index.html',last_transactions=last_transactions)


from flask import request

@app.route('/history')
def history():
    # Get sorting/filtering parameters from query string
    sort_by = request.args.get('sort_by', 'timestamp')  # Default sort by timestamp
    sort_order = request.args.get('sort_order', 'desc')  # Default descending order
    status_filter = request.args.get('status', None)  # Filter by status
    min_amount = request.args.get('min_amount', None)  # Filter by minimum amount
    max_amount = request.args.get('max_amount', None)  # Filter by maximum amount
    start_date = request.args.get('start_date', None)  # Filter by start date
    end_date = request.args.get('end_date', None)  # Filter by end date

    query = 'SELECT receiver_address, amount, timestamp, status FROM transactions WHERE 1=1'

    # Apply filters
    if status_filter:
        query += f" AND status = '{status_filter}'"
    if min_amount:
        query += f" AND amount >= {min_amount}"
    if max_amount:
        query += f" AND amount <= {max_amount}"
    if start_date:
        query += f" AND timestamp >= '{start_date}'"
    if end_date:
        query += f" AND timestamp <= '{end_date}'"

    # Apply sorting
    query += f' ORDER BY {sort_by} {sort_order}'

    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute(query)
    transactions = cursor.fetchall()
    conn.close()

    return render_template('history.html', transactions=transactions, sort_by=sort_by, sort_order=sort_order, status_filter=status_filter, min_amount=min_amount, max_amount=max_amount, start_date=start_date, end_date=end_date)


@app.route('/export/pdf')
def export_pdf():
    # Create a PDF in memory
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Title
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, height - 50, "Transaction History")

    # Table Headers
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, height - 80, "Receiver's Address")
    p.drawString(350, height - 80, "Amount (BTC)")  # BTC amount position remains here
    p.drawString(450, height - 80, "Time")           # Time position remains here
    p.drawString(550, height - 80, "Status")         # Status remains in place

    # Table Data
    p.setFont("Helvetica", 12)
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('SELECT receiver_address, amount, timestamp, status FROM transactions ORDER BY timestamp DESC')
    transactions = cursor.fetchall()
    
    y = height - 100
    for transaction in transactions:
        # Draw each cell with a fixed width
        receiver_address = transaction[0]
        amount = str(transaction[1])
        time = str(transaction[2])
        status = transaction[3]

        # Set maximum width for the receiver address and wrap text if necessary
        receiver_address = receiver_address if len(receiver_address) <= 40 else receiver_address[:37] + '...'  # Truncate for display
        p.drawString(50, y, receiver_address)

        # Draw amount (reduced space for BTC amount)
        p.drawString(350, y, amount)

        # Set maximum width for time and truncate if necessary
        time = time if len(time) <= 30 else time[:27] + '...'  # Longer truncation to fit more
        p.drawString(450, y, time)

        # Draw status
        p.drawString(550, y, status)

        y -= 30  # Increase the spacing between rows

    p.showPage()
    p.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='transaction_history.pdf', mimetype='application/pdf')


@app.route('/qr')
def qr():
    # Generate QR code for the BTC address
    img = qrcode.make(btc_address)

    # Save the image to a BytesIO object
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

@app.route('/process_scan', methods=['POST'])
def process_scan():
    if 'image' not in request.files:
        return jsonify({'status': 'error', 'message': 'No image uploaded.'}), 400

    image_file = request.files['image']
    if image_file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file.'}), 400

    try:
        # Read and decode the image
        image_stream = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(image_stream, cv2.IMREAD_COLOR)
        
        # Check if the image was decoded properly
        if img is None:
            return jsonify({'status': 'error', 'message': 'Could not decode image.'}), 400

        detector = cv2.QRCodeDetector()
        qr_data, points, _ = detector.detectAndDecode(img)

        # Debugging output
        print(f"QR DATA: {qr_data}")

        if qr_data is None or qr_data == '':
            return jsonify({'status': 'error', 'message': 'No QR code data found.'}), 400
        
        if not is_valid_btc_address(qr_data):
            return jsonify({'status': 'error', 'message': 'Invalid Bitcoin address.'}), 400

        return jsonify({'status': 'success', 'address': qr_data})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    if 'image' not in request.files:
        return jsonify({'status': 'error', 'message': 'No image uploaded.'}), 400

    image_file = request.files['image']
    if image_file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file.'}), 400

    try:
        image_stream = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(image_stream, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        qr_data, points, _ = detector.detectAndDecode(img)

        if not qr_data :
            return jsonify({'status': 'error', 'message': 'No QR.'}), 400
        
        if not is_valid_btc_address(qr_data):
            print(f"QR DATA: {qr_data}")
            return jsonify({'status': 'error', 'message': 'Invalid !  Bitcoin address.'}), 400


        return jsonify({'status': 'success', 'address': qr_data})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
 
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
