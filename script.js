// EncryptEase Frontend JavaScript

let currentUser = null;

// Check login status on page load
document.addEventListener('DOMContentLoaded', () => {
    checkLoginStatus();
    setupEventListeners();
});

// Setup all event listeners
function setupEventListeners() {
    // Auth forms - these exist on page load
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
}

// Setup operation event listeners (called when app section is shown)
function setupOperationListeners() {
    // Operation forms
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const hashForm = document.getElementById('hash-form');
    
    if (encryptForm) {
        encryptForm.addEventListener('submit', handleEncrypt);
    }
    if (decryptForm) {
        decryptForm.addEventListener('submit', handleDecrypt);
    }
    if (hashForm) {
        hashForm.addEventListener('submit', handleHash);
    }
    
    // File input change handlers
    const encryptFile = document.getElementById('encrypt-file');
    const decryptFile = document.getElementById('decrypt-file');
    const hashFile = document.getElementById('hash-file');
    
    if (encryptFile) {
        encryptFile.addEventListener('change', (e) => {
            updateFileName('encrypt-file-name', e.target.files[0]);
        });
    }
    if (decryptFile) {
        decryptFile.addEventListener('change', (e) => {
            updateFileName('decrypt-file-name', e.target.files[0]);
        });
    }
    if (hashFile) {
        hashFile.addEventListener('change', (e) => {
            updateFileName('hash-file-name', e.target.files[0]);
        });
    }
}

// Check if user is already logged in
async function checkLoginStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        if (data.logged_in) {
            currentUser = data.username;
            showAppSection();
        }
    } catch (error) {
        console.error('Status check failed:', error);
    }
}

// Tab switching for auth
function switchTab(tab) {
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const tabs = document.querySelectorAll('#auth-section .tab-btn');
    
    tabs.forEach(btn => btn.classList.remove('active'));
    
    if (tab === 'login') {
        loginForm.style.display = 'block';
        registerForm.style.display = 'none';
        tabs[0].classList.add('active');
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
        tabs[1].classList.add('active');
    }
}

// Tab switching for operations
function switchOperation(operation) {
    const sections = ['encrypt', 'decrypt', 'hash'];
    const tabs = document.querySelectorAll('#app-section .tab-btn');
    
    tabs.forEach(btn => btn.classList.remove('active'));
    
    sections.forEach((sec, index) => {
        const section = document.getElementById(`${sec}-section`);
        if (sec === operation) {
            section.style.display = 'block';
            tabs[index].classList.add('active');
        } else {
            section.style.display = 'none';
        }
    });
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();
    
    if (!username || !password) {
        showError('Please enter username and password');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.username;
            showSuccess('Login successful!');
            setTimeout(() => showAppSection(), 500);
        } else {
            showError(data.message || 'Login failed');
        }
    } catch (error) {
        showError('Network error. Please try again.');
        console.error('Login error:', error);
    } finally {
        showLoading(false);
    }
}

// Handle registration
async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value.trim();
    const confirm = document.getElementById('register-confirm').value.trim();
    
    if (!username || !password || !confirm) {
        showError('Please fill in all fields');
        return;
    }
    
    if (password !== confirm) {
        showError('Passwords do not match');
        return;
    }
    
    if (password.length < 6) {
        showError('Password must be at least 6 characters');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('Registration successful! Please login.');
            setTimeout(() => {
                switchTab('login');
                document.getElementById('register-form').reset();
            }, 1000);
        } else {
            showError(data.message || 'Registration failed');
        }
    } catch (error) {
        showError('Network error. Please try again.');
        console.error('Registration error:', error);
    } finally {
        showLoading(false);
    }
}

// Handle logout
async function logout() {
    showLoading(true);
    
    try {
        await fetch('/api/logout', {
            method: 'POST',
        });
        
        currentUser = null;
        showAuthSection();
        showSuccess('Logged out successfully');
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        showLoading(false);
    }
}

// Handle file encryption
async function handleEncrypt(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('encrypt-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file');
        return;
    }
    
    showLoading(true);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/encrypt', {
            method: 'POST',
            body: formData,
        });
        
        const data = await response.json();
        
        if (data.success) {
            showResult('encrypt-result', {
                success: true,
                title: 'File Encrypted Successfully!',
                message: `Your file has been encrypted with AES-256-GCM encryption.`,
                filename: data.filename,
                hash: data.hash,
                downloadUrl: data.download_url,
            });
            fileInput.value = '';
            document.getElementById('encrypt-file-name').textContent = '';
        } else {
            showResult('encrypt-result', {
                success: false,
                title: 'Encryption Failed',
                message: data.message,
            });
        }
    } catch (error) {
        showResult('encrypt-result', {
            success: false,
            title: 'Encryption Failed',
            message: 'Network error. Please try again.',
        });
        console.error('Encryption error:', error);
    } finally {
        showLoading(false);
    }
}

// Handle file decryption
async function handleDecrypt(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('decrypt-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file');
        return;
    }
    
    showLoading(true);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/decrypt', {
            method: 'POST',
            body: formData,
        });
        
        const data = await response.json();
        
        if (data.success) {
            showResult('decrypt-result', {
                success: true,
                title: 'File Decrypted Successfully!',
                message: `Your file has been decrypted.`,
                filename: data.filename,
                hash: data.hash,
                downloadUrl: data.download_url,
            });
            fileInput.value = '';
            document.getElementById('decrypt-file-name').textContent = '';
        } else {
            showResult('decrypt-result', {
                success: false,
                title: 'Decryption Failed',
                message: data.message,
            });
        }
    } catch (error) {
        showResult('decrypt-result', {
            success: false,
            title: 'Decryption Failed',
            message: 'Network error. Please try again.',
        });
        console.error('Decryption error:', error);
    } finally {
        showLoading(false);
    }
}

// Handle file hash calculation
async function handleHash(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('hash-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file');
        return;
    }
    
    showLoading(true);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/hash', {
            method: 'POST',
            body: formData,
        });
        
        const data = await response.json();
        
        if (data.success) {
            showResult('hash-result', {
                success: true,
                title: 'Hash Calculated Successfully!',
                message: `SHA-256 hash for ${data.filename}:`,
                hash: data.hash,
            });
            fileInput.value = '';
            document.getElementById('hash-file-name').textContent = '';
        } else {
            showResult('hash-result', {
                success: false,
                title: 'Hash Calculation Failed',
                message: data.message,
            });
        }
    } catch (error) {
        showResult('hash-result', {
            success: false,
            title: 'Hash Calculation Failed',
            message: 'Network error. Please try again.',
        });
        console.error('Hash error:', error);
    } finally {
        showLoading(false);
    }
}

// Update file name display
function updateFileName(elementId, file) {
    const element = document.getElementById(elementId);
    if (file) {
        element.textContent = file.name;
    } else {
        element.textContent = '';
    }
}

// Show result section
function showResult(resultId, data) {
    const resultDiv = document.getElementById(resultId);
    resultDiv.style.display = 'block';
    
    const className = data.success ? 'result' : 'result error';
    const icon = data.success ? '✓' : '✗';
    
    let html = `
        <h3>${icon} ${data.title}</h3>
        <p>${data.message}</p>
    `;
    
    if (data.hash) {
        html += `
            <div class="hash-value">${data.hash}</div>
        `;
    }
    
    if (data.downloadUrl) {
        html += `
            <a href="${data.downloadUrl}" class="btn btn-primary">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
                Download ${data.filename}
            </a>
        `;
    }
    
    resultDiv.className = className;
    resultDiv.innerHTML = html;
    
    // Scroll to result
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Show/hide loading overlay
function showLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = show ? 'flex' : 'none';
    }
}

// Show auth section
function showAuthSection() {
    const authSection = document.getElementById('auth-section');
    const appSection = document.getElementById('app-section');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    
    if (authSection) authSection.style.display = 'block';
    if (appSection) appSection.style.display = 'none';
    if (loginForm) loginForm.reset();
    if (registerForm) registerForm.reset();
}

// Show app section
function showAppSection() {
    const authSection = document.getElementById('auth-section');
    const appSection = document.getElementById('app-section');
    const usernameDisplay = document.getElementById('username-display');
    
    if (authSection) authSection.style.display = 'none';
    if (appSection) appSection.style.display = 'block';
    if (usernameDisplay) usernameDisplay.textContent = currentUser;
    
    // Setup operation event listeners
    setupOperationListeners();
    
    // Reset all forms and results safely
    const encryptForm = document.getElementById('encrypt-form');
    const decryptForm = document.getElementById('decrypt-form');
    const hashForm = document.getElementById('hash-form');
    
    if (encryptForm) encryptForm.reset();
    if (decryptForm) decryptForm.reset();
    if (hashForm) hashForm.reset();
    
    const encryptResult = document.getElementById('encrypt-result');
    const decryptResult = document.getElementById('decrypt-result');
    const hashResult = document.getElementById('hash-result');
    
    if (encryptResult) encryptResult.style.display = 'none';
    if (decryptResult) decryptResult.style.display = 'none';
    if (hashResult) hashResult.style.display = 'none';
    
    // Show encrypt tab by default
    switchOperation('encrypt');
}

// Show error message
function showError(message) {
    alert('Error: ' + message);
}

// Show success message
function showSuccess(message) {
    alert(message);
}
