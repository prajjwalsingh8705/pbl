# === auth.py ===
"""
Authentication module: PBKDF2-based signup and login.
Stores users in users.json with fields: salt (base64) and pwd_hash (base64).
Provides: register_user(username, password), verify_user(username, password), get_user_salt(username)
"""

import os
import json
import base64
import hashlib
from typing import Optional

USERS_FILE = 'users.json'

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
    return hashlib.compare_digest(pwd_hash, expected)

def get_user_salt(username: str) -> Optional[bytes]:
    users = _load_users()
    if username not in users:
        return None
    return base64.b64decode(users[username]['salt'])


# === crypto.py ===
"""
Crypto engine using AES-256-GCM (authenticated encryption).
Key derivation uses PBKDF2 (compatible with auth salt) so that user password can be used as key material.
Functions:
- derive_key_from_password(password, salt) -> 32-byte key
- encrypt_file(input_path, output_path, key)
- decrypt_file(input_path, output_path, key)

Encrypted file format: [12-byte nonce][ciphertext]
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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


# === integrity.py ===
"""
Simple SHA-256 hashing utilities for files.
Functions:
- file_sha256(path) -> hex digest
"""

import hashlib


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# === gui.py ===
"""
Tkinter GUI. Two windows: Login/Register and Main App.
Login keeps the username and password in memory for deriving keys (never stored in plain on disk).
Main window allows selecting a file and encrypting/decrypting using AES-GCM keyed from the logged-in password+salt.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os

import auth
import crypto
import integrity


class App:
    def __init__(self, root):
        self.root = root
        self.root.title('EncryptEase - Phase 2')
        self.username = None
        self.password = None  # kept in memory for deriving key
        self._build_login()

    def _build_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text='Username').grid(row=0, column=0, sticky='w')
        self.username_entry = ttk.Entry(frame)
        self.username_entry.grid(row=0, column=1)

        ttk.Label(frame, text='Password').grid(row=1, column=0, sticky='w')
        self.password_entry = ttk.Entry(frame, show='*')
        self.password_entry.grid(row=1, column=1)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text='Login', command=self._login).pack(side='left', padx=5)
        ttk.Button(btn_frame, text='Register', command=self._register).pack(side='left', padx=5)

    def _login(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            messagebox.showerror('Error', 'Enter username and password')
            return
        ok = auth.verify_user(u, p)
        if ok:
            self.username = u
            self.password = p
            messagebox.showinfo('Success', 'Login successful')
            self._build_main()
        else:
            messagebox.showerror('Error', 'Invalid credentials')

    def _register(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            messagebox.showerror('Error', 'Enter username and password')
            return
        ok = auth.register_user(u, p)
        if ok:
            messagebox.showinfo('Success', 'Registration complete. You can log in now.')
        else:
            messagebox.showerror('Error', 'Username exists')

    def _build_main(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text=f'Logged in as: {self.username}').grid(row=0, column=0, columnspan=3, sticky='w')

        ttk.Button(frame, text='Select File', command=self._select_file).grid(row=1, column=0, pady=5)
        self.file_label = ttk.Label(frame, text='No file selected')
        self.file_label.grid(row=1, column=1, columnspan=2, sticky='w')

        ttk.Label(frame, text='Output Path (optional)').grid(row=2, column=0, sticky='w')
        self.out_entry = ttk.Entry(frame, width=40)
        self.out_entry.grid(row=2, column=1, columnspan=2, sticky='w')

        ttk.Button(frame, text='Encrypt', command=self._encrypt).grid(row=3, column=0, pady=8)
        ttk.Button(frame, text='Decrypt', command=self._decrypt).grid(row=3, column=1, pady=8)
        ttk.Button(frame, text='Show Hash', command=self._show_hash).grid(row=3, column=2, pady=8)

        self.status = ttk.Label(frame, text='Ready')
        self.status.grid(row=4, column=0, columnspan=3, sticky='w', pady=8)

        self.selected_file = None

    def _select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.selected_file = p
            self.file_label.config(text=os.path.basename(p))

    def _derive_key(self):
        salt = auth.get_user_salt(self.username)
        if salt is None:
            raise RuntimeError('User salt not found')
        key = crypto.derive_key_from_password(self.password, salt)
        return key

    def _encrypt(self):
        if not self.selected_file:
            messagebox.showerror('Error', 'Select a file first')
            return
        out = self.out_entry.get().strip() or (self.selected_file + '.enc')
        self._run_background(lambda: self._do_encrypt(out))

    def _decrypt(self):
        if not self.selected_file:
            messagebox.showerror('Error', 'Select a file first')
            return
        out = self.out_entry.get().strip() or (self.selected_file + '.dec')
        self._run_background(lambda: self._do_decrypt(out))

    def _show_hash(self):
        if not self.selected_file:
            messagebox.showerror('Error', 'Select a file first')
            return
        self._run_background(self._do_hash)

    def _do_encrypt(self, out):
        try:
            key = self._derive_key()
            crypto.encrypt_file(self.selected_file, out, key)
            self.status.config(text=f'Encrypted to {out}')
            messagebox.showinfo('Success', f'File encrypted to {out}')
        except Exception as e:
            self.status.config(text='Encryption failed')
            messagebox.showerror('Error', str(e))

    def _do_decrypt(self, out):
        try:
            key = self._derive_key()
            crypto.decrypt_file(self.selected_file, out, key)
            self.status.config(text=f'Decrypted to {out}')
            messagebox.showinfo('Success', f'File decrypted to {out}')
        except Exception as e:
            self.status.config(text='Decryption failed')
            messagebox.showerror('Error', str(e))

    def _do_hash(self):
        try:
            h = integrity.file_sha256(self.selected_file)
            self.status.config(text=f'SHA256: {h}')
            messagebox.showinfo('File Hash', f'SHA256:\n{h}')
        except Exception as e:
            self.status.config(text='Hash failed')
            messagebox.showerror('Error', str(e))

    def _run_background(self, func):
        self.status.config(text='Processing...')
        threading.Thread(target=func, daemon=True).start()


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
