// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyB4R88Z49bHGPq4xGGDMaKyEqorrYAbOIE",
    authDomain: "linkit-32d13.firebaseapp.com",
    databaseURL: "https://linkit-32d13-default-rtdb.europe-west1.firebasedatabase.app",
    projectId: "linkit-32d13",
    storageBucket: "linkit-32d13.appspot.com",
    messagingSenderId: "263530134949",
    appId: "1:263530134949:web:ead6c09dffa2510ce3fc4c"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const database = firebase.database();

// Security: Encryption key (in production, this should be more complex and possibly server-derived)
const ENCRYPTION_SALT = 'LinkIT_SecureAuth_2024_v1';

// Encrypt data for localStorage
async function encryptData(data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data + ENCRYPTION_SALT);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Return base64 encoded combination of data and hash
    const combined = btoa(data + '|' + hashHex);
    return combined;
}

// Decrypt and verify data from localStorage
async function decryptData(encryptedData) {
    try {
        const decoded = atob(encryptedData);
        const [data, storedHash] = decoded.split('|');
        
        // Verify hash
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data + ENCRYPTION_SALT);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const calculatedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (calculatedHash === storedHash) {
            return data;
        } else {
            // Data has been tampered with
            console.warn('LocalStorage data has been tampered with!');
            return null;
        }
    } catch (error) {
        console.error('Error decrypting data:', error);
        return null;
    }
}

// Secure storage functions
async function setSecureStorage(key, value) {
    const encrypted = await encryptData(value);
    localStorage.setItem(key, encrypted);
}

async function getSecureStorage(key) {
    const encrypted = localStorage.getItem(key);
    if (!encrypted) return null;
    return await decryptData(encrypted);
}

// Monitor device status in real-time for ban/unban detection
function monitorDeviceStatus(deviceId) {
    const deviceRef = database.ref('verified_devices/' + deviceId);
    
    deviceRef.on('value', (snapshot) => {
        const data = snapshot.val();
        
        if (data) {
            // Check if banned status changed
            if (data.banned === true) {
                alert('Your account has been banned.');
                // Clear storage and reload
                localStorage.clear();
                window.location.reload();
            }
            
            // Check if unbanned (status changed from banned to active)
            if (data.status === 'active' && !data.banned && data.wasBanned) {
                alert('Your account has been unbanned!');
                window.location.reload();
            }
        } else {
            // Device data was deleted
            alert('Your device authorization has been revoked.');
            localStorage.clear();
            window.location.reload();
        }
    });
}

// Global variables
let currentCode = '';
let timerInterval;
let autoCloseTimeout;
let currentDeviceFingerprint = '';

// Generate browser/device fingerprint (similar to HWID but for web)
async function generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('fingerprint', 2, 2);
    const canvasData = canvas.toDataURL();
    
    const fingerprint = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        canvas: canvasData,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory || 'unknown',
        colorDepth: screen.colorDepth
    };
    
    const fingerprintString = JSON.stringify(fingerprint);
    
    // Create hash of fingerprint
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
}

// Check if device is already verified
async function checkDeviceVerification() {
    try {
        // Generate device fingerprint
        currentDeviceFingerprint = await generateDeviceFingerprint();
        
        // Strategy 1: Check if we have a stored device ID in secure localStorage
        const storedDeviceId = await getSecureStorage('linkit_device_id');
        
        if (storedDeviceId) {
            // Verify this device ID actually exists and matches our fingerprint
            const deviceRef = database.ref('verified_devices/' + storedDeviceId);
            const snapshot = await deviceRef.once('value');
            const deviceData = snapshot.val();
            
            // Security check: Verify the stored ID matches the fingerprint in Firebase
            if (deviceData && deviceData.browserFingerprint === currentDeviceFingerprint) {
                if (deviceData.status === 'active' && !deviceData.banned) {
                    // Update last login time
                    await deviceRef.update({
                        lastWebLogin: Date.now()
                    });
                    
                    // Store encrypted ID in Firebase if not already there
                    const encryptedDeviceId = localStorage.getItem('linkit_device_id');
                    if (encryptedDeviceId && !deviceData.encryptedDeviceId) {
                        await deviceRef.update({
                            encryptedDeviceId: encryptedDeviceId
                        });
                    }
                    
                    // Start monitoring for ban status changes
                    monitorDeviceStatus(storedDeviceId);
                    
                    if (deviceData.username) {
                        autoLogin(deviceData);
                        return true;
                    } else if (deviceData.needsUsername) {
                        window.currentDeviceId = storedDeviceId;
                        showUsernameSection(storedDeviceId);
                        return true;
                    }
                } else if (deviceData.banned) {
                    showBannedMessage();
                    return true;
                }
            } else {
                // Device ID doesn't match fingerprint - possible tampering!
                console.warn('Device ID tampering detected! Clearing localStorage.');
                localStorage.clear();
                // Fall through to Strategy 2
            }
        }
        
        // Strategy 2: Check all devices to see if any match our browser fingerprint
        const devicesRef = database.ref('verified_devices');
        const allDevicesSnapshot = await devicesRef.once('value');
        const allDevices = allDevicesSnapshot.val();
        
        if (allDevices) {
            for (let deviceId in allDevices) {
                const deviceData = allDevices[deviceId];
                
                // Check if browser fingerprint matches
                if (deviceData.browserFingerprint === currentDeviceFingerprint) {
                    if (deviceData.status === 'active' && !deviceData.banned) {
                        // Store device ID securely for future quick access
                        await setSecureStorage('linkit_device_id', deviceId);
                        
                        // Update last login
                        await devicesRef.child(deviceId).update({
                            lastWebLogin: Date.now()
                        });
                        
                        // Start monitoring for ban status changes
                        monitorDeviceStatus(deviceId);
                        
                        if (deviceData.username) {
                            autoLogin(deviceData);
                            return true;
                        } else if (deviceData.needsUsername) {
                            window.currentDeviceId = deviceId;
                            showUsernameSection(deviceId);
                            return true;
                        }
                    } else if (deviceData.banned) {
                        showBannedMessage();
                        return true;
                    }
                }
            }
        }
        
        return false;
    } catch (error) {
        console.error('Error checking device verification:', error);
        return false;
    }
}

// Auto-login for verified devices
function autoLogin(userData) {
    // Start monitoring device status for bans
    const deviceId = Object.keys(userData).length > 0 ? window.currentDeviceId : null;
    if (deviceId) {
        monitorDeviceStatus(deviceId);
    }
    
    // Redirect to dashboard
    window.location.href = 'dashboard.html';
}

// Show banned message
function showBannedMessage() {
    const loginSection = document.getElementById('loginSection');
    loginSection.style.display = 'none';
    
    const container = document.querySelector('.login-card');
    container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
            <div style="width: 80px; height: 80px; background: var(--error); border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 48px;">⛔</div>
            <h2 class="section-title" style="color: var(--error);">Account Banned</h2>
            <p class="section-subtitle">This device has been banned from accessing the service.</p>
            <p style="color: var(--text-secondary); margin-top: 20px;">Please contact support for more information.</p>
        </div>
    `;
}

// Generate unique verification code with format XX-XX-XXX-X
function generateVerificationCode() {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&*';
    let code = '';
    
    // Generate 8 random characters
    for (let i = 0; i < 8; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        code += characters[randomIndex];
    }
    
    // Format as XX-XX-XXX-X
    return `${code.slice(0, 2)}-${code.slice(2, 4)}-${code.slice(4, 7)}-${code.slice(7, 8)}`;
}

// Register verification code in Firebase
async function registerCodeInDatabase(code) {
    const codeRef = database.ref('verification_codes/' + code.replace(/-/g, '_'));
    const expiresAt = Date.now() + (3 * 60 * 1000); // 3 minutes from now
    
    try {
        await codeRef.set({
            code: code,
            status: 'pending',
            createdAt: Date.now(),
            expiresAt: expiresAt,
            used: false
        });
        
        // Set up automatic expiration
        setTimeout(async () => {
            const snapshot = await codeRef.once('value');
            const data = snapshot.val();
            
            if (data && !data.used) {
                await codeRef.update({
                    status: 'expired',
                    expiredAt: Date.now()
                });
            }
        }, 3 * 60 * 1000);
        
        return true;
    } catch (error) {
        console.error('Error registering code:', error);
        return false;
    }
}

// Start countdown timer
function startTimer() {
    let timeLeft = 180; // 3 minutes in seconds
    const timerDisplay = document.getElementById('timerDisplay');
    
    timerInterval = setInterval(() => {
        timeLeft--;
        
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        timerDisplay.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timerDisplay.textContent = 'EXPIRED';
            timerDisplay.style.color = 'var(--error)';
        }
    }, 1000);
}

// Download Python verification app
function downloadVerificationApp() {
    // Show download status
    const downloadStatus = document.getElementById('downloadStatus');
    downloadStatus.classList.add('active');
    
    // Create the Python app content
    const pythonAppCode = `import tkinter as tk
from tkinter import messagebox
import firebase_admin
from firebase_admin import credentials, db
import platform
import subprocess
import hashlib
import time

# Firebase initialization
cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': '${firebaseConfig.databaseURL}'
})

def get_hwid():
    """Get unique hardware ID for this PC"""
    if platform.system() == 'Windows':
        cmd = 'wmic csproduct get uuid'
        hwid = subprocess.check_output(cmd).decode().split('\\n')[1].strip()
    else:
        # For Linux/Mac, use machine-id or create one
        try:
            with open('/etc/machine-id', 'r') as f:
                hwid = f.read().strip()
        except:
            hwid = str(hash(platform.node()))
    
    return hashlib.sha256(hwid.encode()).hexdigest()

class LinkITApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LinkIT Verification")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        self.hwid = get_hwid()
        
        # Check if already verified
        if self.check_existing_verification():
            self.show_already_verified()
        else:
            self.create_verification_ui()
    
    def check_existing_verification(self):
        """Check if this device is already verified"""
        try:
            devices_ref = db.reference('verified_devices')
            devices = devices_ref.order_by_child('hwid').equal_to(self.hwid).get()
            
            if devices:
                for device_id, device_data in devices.items():
                    if device_data.get('status') == 'active' and not device_data.get('banned', False):
                        self.user_data = device_data
                        return True
            return False
        except Exception as e:
            print(f"Error checking verification: {e}")
            return False
    
    def show_already_verified(self):
        """Show verification complete message"""
        frame = tk.Frame(self.root, bg='#1e293b')
        frame.pack(expand=True, fill='both')
        
        tk.Label(
            frame,
            text="✓ Verification Complete",
            font=('Poppins', 18, 'bold'),
            bg='#1e293b',
            fg='#10b981'
        ).pack(pady=20)
        
        tk.Label(
            frame,
            text="Your device is already linked",
            font=('Poppins', 12),
            bg='#1e293b',
            fg='#94a3b8'
        ).pack(pady=10)
        
        # Auto-close after 5 seconds
        self.root.after(5000, self.root.destroy)
        
        # Show countdown
        self.countdown_label = tk.Label(
            frame,
            text="Closing in 5 seconds...",
            font=('Poppins', 10),
            bg='#1e293b',
            fg='#94a3b8'
        )
        self.countdown_label.pack(pady=20)
        self.start_countdown(5)
    
    def start_countdown(self, seconds):
        """Countdown timer"""
        if seconds > 0:
            self.countdown_label.config(text=f"Closing in {seconds} seconds...")
            self.root.after(1000, lambda: self.start_countdown(seconds - 1))
    
    def create_verification_ui(self):
        """Create verification code input UI"""
        frame = tk.Frame(self.root, bg='#1e293b')
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        tk.Label(
            frame,
            text="LinkIT Verification",
            font=('Poppins', 20, 'bold'),
            bg='#1e293b',
            fg='#f1f5f9'
        ).pack(pady=20)
        
        # Instructions
        tk.Label(
            frame,
            text="Enter your verification code",
            font=('Poppins', 11),
            bg='#1e293b',
            fg='#94a3b8'
        ).pack(pady=10)
        
        # Code entry
        self.code_entry = tk.Entry(
            frame,
            font=('Courier New', 16, 'bold'),
            justify='center',
            bg='#0f172a',
            fg='#3b82f6',
            insertbackground='#3b82f6',
            relief='flat',
            bd=2
        )
        self.code_entry.pack(pady=10, ipady=10, fill='x')
        self.code_entry.focus()
        
        # Format hint
        tk.Label(
            frame,
            text="Format: XX-XX-XXX-X or XXXXXXXX",
            font=('Poppins', 9),
            bg='#1e293b',
            fg='#64748b'
        ).pack(pady=5)
        
        # Verify button
        verify_btn = tk.Button(
            frame,
            text="Verify",
            font=('Poppins', 12, 'bold'),
            bg='#3b82f6',
            fg='white',
            relief='flat',
            cursor='hand2',
            command=self.verify_code
        )
        verify_btn.pack(pady=20, fill='x', ipady=10)
        
        # Bind Enter key
        self.code_entry.bind('<Return>', lambda e: self.verify_code())
    
    def normalize_code(self, code):
        """Remove dashes from code for comparison"""
        return code.replace('-', '').upper()
    
    def verify_code(self):
        """Verify the entered code"""
        entered_code = self.code_entry.get().strip()
        
        if not entered_code:
            messagebox.showerror("Error", "Please enter a verification code")
            return
        
        # Normalize code (remove dashes)
        normalized_code = self.normalize_code(entered_code)
        
        try:
            # Check all possible formats in database
            codes_ref = db.reference('verification_codes')
            all_codes = codes_ref.get()
            
            code_found = False
            code_key = None
            code_data = None
            
            if all_codes:
                for key, data in all_codes.items():
                    db_code = self.normalize_code(data.get('code', ''))
                    if db_code == normalized_code:
                        code_found = True
                        code_key = key
                        code_data = data
                        break
            
            if not code_found:
                messagebox.showerror("Error", "Invalid verification code")
                return
            
            # Check if code is expired
            if code_data.get('status') == 'expired' or code_data.get('expiresAt', 0) < time.time() * 1000:
                messagebox.showerror("Error", "Verification code has expired")
                return
            
            # Check if code is already used
            if code_data.get('used', False):
                messagebox.showerror("Error", "Verification code has already been used")
                return
            
            # Mark code as used
            codes_ref.child(code_key).update({
                'used': True,
                'usedAt': int(time.time() * 1000),
                'status': 'verified'
            })
            
            # Register device
            device_id = hashlib.sha256(f"{self.hwid}{time.time()}".encode()).hexdigest()[:16]
            
            devices_ref = db.reference('verified_devices')
            devices_ref.child(device_id).set({
                'hwid': self.hwid,
                'verifiedAt': int(time.time() * 1000),
                'status': 'active',
                'banned': False,
                'needsUsername': True,
                'verificationCode': code_data.get('code')
            })
            
            # Update verification code with device ID
            codes_ref.child(code_key).update({
                'deviceId': device_id
            })
            
            # Show success and close
            messagebox.showinfo("Success", "Verification successful!\\nYour device is now linked.\\nPlease return to the website to complete setup.")
            self.root.after(2000, self.root.destroy)
            
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = LinkITApp(root)
    root.mainloop()
`;

    // Create download blob
    const blob = new Blob([pythonAppCode], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'LinkIT_Verification.py';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    // Update status after 2 seconds
    setTimeout(() => {
        downloadStatus.innerHTML = '✓ LinkIT app downloaded successfully!';
    }, 2000);
}

// Copy code to clipboard
function copyToClipboard() {
    const codeElement = document.getElementById('verificationCode');
    const code = codeElement.textContent;
    
    navigator.clipboard.writeText(code).then(() => {
        const copyBtn = document.getElementById('copyBtn');
        const originalText = copyBtn.innerHTML;
        copyBtn.innerHTML = '✓ Copied!';
        copyBtn.style.background = 'var(--success)';
        copyBtn.style.color = 'white';
        copyBtn.style.borderColor = 'var(--success)';
        
        setTimeout(() => {
            copyBtn.innerHTML = originalText;
            copyBtn.style.background = '';
            copyBtn.style.color = '';
            copyBtn.style.borderColor = '';
        }, 2000);
    });
}

// Close modal
function closeModal() {
    const modal = document.getElementById('instructionModal');
    modal.classList.remove('active');
    clearInterval(timerInterval);
    clearTimeout(autoCloseTimeout);
}

// Monitor verification status in Firebase
function monitorVerificationStatus(code) {
    const codeRef = database.ref('verification_codes/' + code.replace(/-/g, '_'));
    
    codeRef.on('value', async (snapshot) => {
        const data = snapshot.val();
        
        if (data && data.status === 'verified' && data.deviceId) {
            // Store device ID securely in localStorage
            await setSecureStorage('linkit_device_id', data.deviceId);
            
            // Get the encrypted value to store in Firebase too
            const encryptedDeviceId = localStorage.getItem('linkit_device_id');
            
            // Verification successful, update device with browser fingerprint AND encrypted ID
            const deviceRef = database.ref('verified_devices/' + data.deviceId);
            await deviceRef.update({
                browserFingerprint: currentDeviceFingerprint,
                encryptedDeviceId: encryptedDeviceId,
                lastWebLogin: Date.now()
            });
            
            // Start monitoring for ban status changes
            monitorDeviceStatus(data.deviceId);
            
            // Show username section
            clearInterval(timerInterval);
            closeModal();
            showUsernameSection(data.deviceId);
        }
    });
}

// Show username section
function showUsernameSection(deviceId) {
    const loginSection = document.getElementById('loginSection');
    const usernameSection = document.getElementById('usernameSection');
    
    loginSection.style.display = 'none';
    usernameSection.classList.add('active');
    
    // Store device ID for later use
    window.currentDeviceId = deviceId;
}

// Check if username exists (case-insensitive)
async function checkUsernameExists(username) {
    const usernamesRef = database.ref('usernames');
    const snapshot = await usernamesRef.once('value');
    const usernames = snapshot.val();
    
    if (!usernames) return false;
    
    const normalizedInput = username.toLowerCase();
    
    for (let key in usernames) {
        if (usernames[key].toLowerCase() === normalizedInput) {
            return true;
        }
    }
    
    return false;
}

// Submit username
async function submitUsername() {
    const usernameInput = document.getElementById('usernameInput');
    const username = usernameInput.value.trim();
    const errorElement = document.getElementById('usernameError');
    const submitBtn = document.getElementById('submitUsername');
    const submitText = document.getElementById('submitText');
    const submitSpinner = document.getElementById('submitSpinner');
    
    // Validation
    if (!username) {
        errorElement.textContent = 'Username is required';
        errorElement.classList.add('active');
        return;
    }
    
    if (username.length < 3) {
        errorElement.textContent = 'Username must be at least 3 characters';
        errorElement.classList.add('active');
        return;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        errorElement.textContent = 'Username can only contain letters, numbers, and underscores';
        errorElement.classList.add('active');
        return;
    }
    
    // Check if username exists
    submitBtn.disabled = true;
    submitText.style.display = 'none';
    submitSpinner.classList.add('active');
    
    const exists = await checkUsernameExists(username);
    
    if (exists) {
        errorElement.textContent = 'This username is already taken (case-insensitive)';
        errorElement.classList.add('active');
        submitBtn.disabled = false;
        submitText.style.display = 'block';
        submitSpinner.classList.remove('active');
        return;
    }
    
    // Username is available, create account
    try {
        const deviceId = window.currentDeviceId;
        
        // Update device with username
        await database.ref('verified_devices/' + deviceId).update({
            username: username,
            needsUsername: false,
            accountCreatedAt: Date.now()
        });
        
        // Make sure device ID is securely stored
        await setSecureStorage('linkit_device_id', deviceId);
        
        // Add username to usernames list
        await database.ref('usernames').push(username);
        
        // Show success
        errorElement.classList.remove('active');
        submitText.style.display = 'none';
        submitSpinner.classList.remove('active');
        
        const successCheck = document.getElementById('successCheck');
        successCheck.classList.add('active');
        
        // Start monitoring for bans
        monitorDeviceStatus(deviceId);
        
        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 1500);
        
    } catch (error) {
        console.error('Error creating account:', error);
        errorElement.textContent = 'An error occurred. Please try again.';
        errorElement.classList.add('active');
        submitBtn.disabled = false;
        submitText.style.display = 'block';
        submitSpinner.classList.remove('active');
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
    // First, check if device is already verified
    const isVerified = await checkDeviceVerification();
    
    if (isVerified) {
        // Device is already verified, auto-login handled
        return;
    }
    
    // Device not verified, show normal login
    const linkitBtn = document.getElementById('linkitBtn');
    const closeModalBtn = document.getElementById('closeModal');
    const copyBtn = document.getElementById('copyBtn');
    const submitUsernameBtn = document.getElementById('submitUsername');
    const usernameInput = document.getElementById('usernameInput');
    const usernameError = document.getElementById('usernameError');
    
    // LinkIT button click
    linkitBtn.addEventListener('click', async () => {
        // Generate device fingerprint if not already done
        if (!currentDeviceFingerprint) {
            currentDeviceFingerprint = await generateDeviceFingerprint();
        }
        
        // Generate verification code
        currentCode = generateVerificationCode();
        
        // Register code in database
        const registered = await registerCodeInDatabase(currentCode);
        
        if (!registered) {
            alert('Error generating verification code. Please try again.');
            return;
        }
        
        // Show modal
        const modal = document.getElementById('instructionModal');
        const codeDisplay = document.getElementById('verificationCode');
        codeDisplay.textContent = currentCode;
        modal.classList.add('active');
        
        // Start timer
        startTimer();
        
        // Download app
        downloadVerificationApp();
        
        // Set auto-close timeout (10 seconds)
        autoCloseTimeout = setTimeout(() => {
            // Modal will auto-close after 10 seconds, but timer continues
        }, 10000);
        
        // Monitor verification status
        monitorVerificationStatus(currentCode);
    });
    
    // Close modal button
    closeModalBtn.addEventListener('click', closeModal);
    
    // Copy button
    copyBtn.addEventListener('click', copyToClipboard);
    
    // Submit username button
    submitUsernameBtn.addEventListener('click', submitUsername);
    
    // Clear error on input
    usernameInput.addEventListener('input', () => {
        usernameError.classList.remove('active');
    });
    
    // Submit on Enter key
    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            submitUsername();
        }
    });
    
    // Close modal on outside click
    const modal = document.getElementById('instructionModal');
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
});
