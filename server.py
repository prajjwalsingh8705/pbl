"""
Flask Web Server for EncryptEase
Provides REST API endpoints for authentication and file encryption/decryption
"""

from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
import os
import json
import base64
import hashlib
import hmac
from typing import Optional
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = secrets.token_hex(32)
CORS(app)

USERS_FILE = 'users.json'
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'

# Create necessary folders
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# === Authentication Functions ===

def _load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def _save_users(d):
    with open(USERS_FILE, 'w') as f:
        json.dump(d, f, indent=2)

def _pbkdf2_hash(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)

def register_user(username: str, password: str) -> bool:
    users = _load_users()
    if username in users:
        return False
    salt = os.urandom(16)
    pwd_hash = _pbkdf2_hash(password, salt)
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'pwd_hash': base64.b64encode(pwd_hash).decode('utf-8')
    }
    _save_users(users)
    return True

def verify_user(username: str, password: str) -> bool:
    users = _load_users()
    if username not in users:
        return False
    salt = base64.b64decode(users[username]['salt'])
    expected = base64.b64decode(users[username]['pwd_hash'])
    pwd_hash = _pbkdf2_hash(password, salt)
    return hmac.compare_digest(pwd_hash, expected)

def get_user_salt(username: str) -> Optional[bytes]:
    users = _load_users()
    if username not in users:
        return None
    return base64.b64decode(users[username]['salt'])

# === Crypto Functions ===

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(input_path, 'rb') as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    with open(output_path, 'wb') as f:
        f.write(nonce + ct)

def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    aesgcm = AESGCM(key)
    with open(input_path, 'rb') as f:
        blob = f.read()
    nonce = blob[:12]
    ct = blob[12:]
    pt = aesgcm.decrypt(nonce, ct, None)
    with open(output_path, 'wb') as f:
        f.write(pt)

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# === API Routes ===

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
    
    success = register_user(username, password)
    if success:
        return jsonify({'success': True, 'message': 'Registration successful'})
    else:
        return jsonify({'success': False, 'message': 'Username already exists'}), 400

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    
    if verify_user(username, password):
        session['username'] = username
        session['password'] = password  # Store in session for key derivation
        return jsonify({'success': True, 'message': 'Login successful', 'username': username})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        # Derive encryption key
        username = session['username']
        password = session['password']
        salt = get_user_salt(username)
        if salt is None:
            return jsonify({'success': False, 'message': 'User not found'}), 400
        
        key = derive_key_from_password(password, salt)
        
        # Encrypt file
        encrypted_filename = filename + '.enc'
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        encrypt_file(upload_path, encrypted_path, key)
        
        # Calculate hash
        file_hash = file_sha256(upload_path)
        
        # Clean up original file
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'message': 'File encrypted successfully',
            'filename': encrypted_filename,
            'hash': file_hash,
            'download_url': f'/api/download/encrypted/{encrypted_filename}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    try:
        # Save uploaded encrypted file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        # Derive decryption key
        username = session['username']
        password = session['password']
        salt = get_user_salt(username)
        if salt is None:
            return jsonify({'success': False, 'message': 'User not found'}), 400
        
        key = derive_key_from_password(password, salt)
        
        # Decrypt file
        decrypted_filename = filename.replace('.enc', '') if filename.endswith('.enc') else filename + '.dec'
        decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)
        decrypt_file(upload_path, decrypted_path, key)
        
        # Calculate hash
        file_hash = file_sha256(decrypted_path)
        
        # Clean up encrypted file
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'message': 'File decrypted successfully',
            'filename': decrypted_filename,
            'hash': file_hash,
            'download_url': f'/api/download/decrypted/{decrypted_filename}'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/hash', methods=['POST'])
def api_hash():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    try:
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        # Calculate hash
        file_hash = file_sha256(upload_path)
        
        # Clean up
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'hash': file_hash,
            'filename': filename
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hash calculation failed: {str(e)}'}), 500

@app.route('/api/download/encrypted/<filename>')
def download_encrypted(filename):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    file_path = os.path.join(ENCRYPTED_FOLDER, secure_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/api/download/decrypted/<filename>')
def download_decrypted(filename):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    file_path = os.path.join(DECRYPTED_FOLDER, secure_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'File not found'}), 404
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/api/status', methods=['GET'])
def api_status():
    if 'username' in session:
        return jsonify({'logged_in': True, 'username': session['username']})
    else:
        return jsonify({'logged_in': False})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
