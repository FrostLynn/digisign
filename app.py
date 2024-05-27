import os
import qrcode
import datetime
import json
import uuid
import hashlib
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, send_file, jsonify, session, flash
import fitz  # PyMuPDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEY_FOLDER'] = 'keys'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['OWNERSHIP_DATA'] = 'ownership_data.json'
app.config['USERS_DATA'] = 'users_data.json'
app.secret_key = 'supersecretkey'  # Replace with your own secret key

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['KEY_FOLDER']):
    os.makedirs(app.config['KEY_FOLDER'])

if not os.path.exists(app.config['OWNERSHIP_DATA']):
    with open(app.config['OWNERSHIP_DATA'], 'w') as f:
        json.dump({}, f)

if not os.path.exists(app.config['USERS_DATA']):
    with open(app.config['USERS_DATA'], 'w') as f:
        json.dump({}, f)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_keys(file_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(app.config['KEY_FOLDER'], f"{file_id}_private_key.pem")
    public_key_path = os.path.join(app.config['KEY_FOLDER'], f"{file_id}_public_key.pem")

    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    with open(public_key_path, 'wb') as public_file:
        public_file.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def generate_qr_code(data, file_path):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(file_path)

def add_qr_code_to_pdf(pdf_path, qr_code_path, output_path, x, y, size):
    document = fitz.open(pdf_path)
    page = document.load_page(-1)  # last page
    rect = fitz.Rect(x, y, x + size, y + size)  # position and size of the QR code
    page.insert_image(rect, filename=qr_code_path)
    document.save(output_path)

def save_ownership_data(data):
    with open(app.config['OWNERSHIP_DATA'], 'r+') as f:
        ownership_data = json.load(f)
        ownership_data[data['uuid']] = data
        f.seek(0)
        json.dump(ownership_data, f, indent=4)

def clear_upload_folder():
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

def save_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(app.config['USERS_DATA'], 'r+') as f:
        users_data = json.load(f)
        if username in users_data:
            return False
        users_data[username] = hashed_password
        f.seek(0)
        json.dump(users_data, f, indent=4)
    return True

def validate_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(app.config['USERS_DATA'], 'r') as f:
        users_data = json.load(f)
        if username in users_data and users_data[username] == hashed_password:
            return True
    return False

@app.route('/')
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/upload_form')
def upload_form():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    # In the upload_file function
    if file and allowed_file(file.filename):
        name = request.form['name']
        subject = request.form['subject']
        x = int(request.form['x'])
        y = int(request.form['y'])
        size = int(request.form['size'])

        # Use a UUID as the file ID
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.pdf"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        private_key, public_key = generate_keys(file_id)
        data_to_sign = f"{name},{subject}".encode()
        signature = sign_data(private_key, data_to_sign)
        signature_hex = signature.hex()

        qr_code_data = {
            'url': url_for('ownership_proof', file_id=file_id, _external=True),
            'signature': signature_hex
        }
        qr_code_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_qrcode.png")
        generate_qr_code(qr_code_data, qr_code_path)

        signed_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"signed_{filename}")
        add_qr_code_to_pdf(file_path, qr_code_path, signed_file_path, x, y, size)

        ownership_data = {
            'uuid': file_id,
            'name': name,
            'subject': subject,
            'original_filename': file.filename,
            'signed_filename': f"signed_{filename}",
            'signature': signature_hex,
            'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': session['username']
        }
        save_ownership_data(ownership_data)

        return jsonify(filename=f"signed_{filename}")
    return redirect(request.url)

@app.route('/uploads/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/preview/<filename>')
def preview_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/proof/<file_id>')
def ownership_proof(file_id):
    with open(app.config['OWNERSHIP_DATA'], 'r') as f:
        ownership_data = json.load(f)
        if file_id in ownership_data:
            data = ownership_data[file_id]
            signed_pdf_url = url_for('download_file', filename=data['signed_filename'], _external=True)
            return render_template('proof.html', name=data['name'], subject=data['subject'], signature=data['signature'], date=data['date'], signed_pdf_url=signed_pdf_url)
        else:
            return "Ownership proof not found", 404
        
@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_documents = []

    with open(app.config['OWNERSHIP_DATA'], 'r') as f:
        ownership_data = json.load(f)
        for doc in ownership_data.values():
            if doc['username'] == username:
                user_documents.append(doc)

    return render_template('history.html', documents=user_documents)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if save_user(username, password):
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose another.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_user(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
