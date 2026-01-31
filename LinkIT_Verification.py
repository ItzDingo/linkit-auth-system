"""
LinkIT Verification Application
Professional Business Portal - Device Authentication
"""

import tkinter as tk
from tkinter import messagebox
import platform
import subprocess
import hashlib
import time
import json
import sys

# Try to import Firebase Admin SDK
try:
    import firebase_admin
    from firebase_admin import credentials, db
except ImportError:
    print("Firebase Admin SDK not installed!")
    print("Please install it using: pip install firebase-admin")
    sys.exit(1)

# Firebase configuration - Replace with your actual Firebase database URL
FIREBASE_DATABASE_URL = 'https://linkit-32d13-default-rtdb.europe-west1.firebasedatabase.app'
SERVICE_ACCOUNT_PATH = 'serviceAccountKey.json'

def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    try:
        cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
        firebase_admin.initialize_app(cred, {
            'databaseURL': FIREBASE_DATABASE_URL
        })
        return True
    except Exception as e:
        messagebox.showerror("Firebase Error", f"Could not connect to Firebase:\n{str(e)}")
        return False

def get_hwid():
    """Get unique hardware ID for this PC"""
    try:
        if platform.system() == 'Windows':
            # Windows: Use WMIC to get UUID
            cmd = 'wmic csproduct get uuid'
            output = subprocess.check_output(cmd, shell=True).decode()
            hwid = output.split('\n')[1].strip()
        elif platform.system() == 'Darwin':
            # macOS: Use system_profiler
            cmd = "system_profiler SPHardwareDataType | grep 'Serial Number' | awk '{print $4}'"
            hwid = subprocess.check_output(cmd, shell=True).decode().strip()
        else:
            # Linux: Try machine-id
            try:
                with open('/etc/machine-id', 'r') as f:
                    hwid = f.read().strip()
            except:
                # Fallback: use hostname
                hwid = platform.node()
        
        # Hash the HWID for privacy
        return hashlib.sha256(hwid.encode()).hexdigest()
    except Exception as e:
        print(f"Error getting HWID: {e}")
        # Fallback to a combination of system info
        system_info = f"{platform.system()}{platform.node()}{platform.machine()}"
        return hashlib.sha256(system_info.encode()).hexdigest()

class LinkITApp:
    """Main LinkIT Verification Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("LinkIT Verification")
        self.root.geometry("450x350")
        self.root.resizable(False, False)
        self.root.configure(bg='#1e293b')
        
        # Center window
        self.center_window()
        
        # Get hardware ID
        self.hwid = get_hwid()
        
        # Check if already verified
        if self.check_existing_verification():
            self.show_already_verified()
        else:
            self.create_verification_ui()
    
    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def check_existing_verification(self):
        """Check if this device is already verified and not banned"""
        try:
            devices_ref = db.reference('verified_devices')
            devices = devices_ref.order_by_child('hwid').equal_to(self.hwid).get()
            
            if devices:
                for device_id, device_data in devices.items():
                    # Check if device is active and not banned
                    if device_data.get('status') == 'active' and not device_data.get('banned', False):
                        self.device_id = device_id
                        self.user_data = device_data
                        return True
                    elif device_data.get('banned', False):
                        messagebox.showerror(
                            "Account Banned",
                            "This device has been banned from accessing the service.\n\nPlease contact support for more information."
                        )
                        self.root.after(100, self.root.destroy)
                        return True  # Return True to prevent showing verification UI
            return False
        except Exception as e:
            print(f"Error checking verification: {e}")
            return False
    
    def show_already_verified(self):
        """Show verification complete message"""
        frame = tk.Frame(self.root, bg='#1e293b')
        frame.pack(expand=True, fill='both', padx=30, pady=30)
        
        # Success icon (checkmark in circle)
        canvas = tk.Canvas(frame, width=80, height=80, bg='#1e293b', highlightthickness=0)
        canvas.pack(pady=20)
        
        # Draw circle
        canvas.create_oval(10, 10, 70, 70, fill='#10b981', outline='')
        
        # Draw checkmark
        canvas.create_line(25, 40, 35, 50, width=5, fill='white', capstyle='round')
        canvas.create_line(35, 50, 55, 25, width=5, fill='white', capstyle='round')
        
        tk.Label(
            frame,
            text="Verification Complete",
            font=('Segoe UI', 20, 'bold'),
            bg='#1e293b',
            fg='#10b981'
        ).pack(pady=10)
        
        tk.Label(
            frame,
            text="Your device is already linked",
            font=('Segoe UI', 12),
            bg='#1e293b',
            fg='#94a3b8'
        ).pack(pady=5)
        
        if hasattr(self, 'user_data') and 'username' in self.user_data:
            tk.Label(
                frame,
                text=f"Username: {self.user_data['username']}",
                font=('Segoe UI', 11),
                bg='#1e293b',
                fg='#3b82f6'
            ).pack(pady=10)
        
        # Countdown label
        self.countdown_label = tk.Label(
            frame,
            text="Closing in 5 seconds...",
            font=('Segoe UI', 10),
            bg='#1e293b',
            fg='#64748b'
        )
        self.countdown_label.pack(pady=20)
        
        # Auto-close after 5 seconds
        self.start_countdown(5)
        self.root.after(5000, self.root.destroy)
    
    def start_countdown(self, seconds):
        """Countdown timer"""
        if seconds > 0:
            self.countdown_label.config(text=f"Closing in {seconds} second{'s' if seconds > 1 else ''}...")
            self.root.after(1000, lambda: self.start_countdown(seconds - 1))
        else:
            self.countdown_label.config(text="Closing...")
    
    def create_verification_ui(self):
        """Create verification code input UI"""
        frame = tk.Frame(self.root, bg='#1e293b')
        frame.pack(expand=True, fill='both', padx=30, pady=30)
        
        # Logo/Title
        tk.Label(
            frame,
            text="🔐 LinkIT",
            font=('Segoe UI', 28, 'bold'),
            bg='#1e293b',
            fg='#3b82f6'
        ).pack(pady=(0, 5))
        
        tk.Label(
            frame,
            text="Device Verification",
            font=('Segoe UI', 13),
            bg='#1e293b',
            fg='#94a3b8'
        ).pack(pady=(0, 25))
        
        # Instructions
        instructions_frame = tk.Frame(frame, bg='#0f172a', relief='flat', bd=0)
        instructions_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(
            instructions_frame,
            text="Enter your verification code from the website",
            font=('Segoe UI', 10),
            bg='#0f172a',
            fg='#cbd5e1',
            wraplength=350,
            justify='center'
        ).pack(pady=15)
        
        # Code entry
        self.code_entry = tk.Entry(
            frame,
            font=('Courier New', 18, 'bold'),
            justify='center',
            bg='#0f172a',
            fg='#3b82f6',
            insertbackground='#3b82f6',
            relief='flat',
            bd=2,
            highlightthickness=2,
            highlightbackground='#334155',
            highlightcolor='#3b82f6'
        )
        self.code_entry.pack(pady=10, ipady=12, fill='x')
        self.code_entry.focus()
        
        # Format hint
        tk.Label(
            frame,
            text="Format: XX-XX-XXX-X or XXXXXXXX",
            font=('Segoe UI', 9),
            bg='#1e293b',
            fg='#64748b'
        ).pack(pady=(5, 20))
        
        # Verify button
        self.verify_btn = tk.Button(
            frame,
            text="Verify Device",
            font=('Segoe UI', 12, 'bold'),
            bg='#3b82f6',
            fg='white',
            activebackground='#2563eb',
            activeforeground='white',
            relief='flat',
            cursor='hand2',
            command=self.verify_code,
            bd=0,
            highlightthickness=0
        )
        self.verify_btn.pack(pady=10, fill='x', ipady=12)
        
        # Bind Enter key
        self.code_entry.bind('<Return>', lambda e: self.verify_code())
        
        # Add hover effect
        self.verify_btn.bind('<Enter>', lambda e: self.verify_btn.config(bg='#2563eb'))
        self.verify_btn.bind('<Leave>', lambda e: self.verify_btn.config(bg='#3b82f6'))
    
    def normalize_code(self, code):
        """Remove dashes and convert to uppercase for comparison"""
        return code.replace('-', '').replace(' ', '').upper()
    
    def verify_code(self):
        """Verify the entered code against Firebase"""
        entered_code = self.code_entry.get().strip()
        
        # Validation
        if not entered_code:
            messagebox.showwarning("Input Required", "Please enter a verification code")
            return
        
        # Disable button and show processing
        self.verify_btn.config(state='disabled', text='Verifying...', bg='#64748b')
        self.root.update()
        
        # Normalize entered code
        normalized_entered = self.normalize_code(entered_code)
        
        try:
            # Search for matching code in database
            codes_ref = db.reference('verification_codes')
            all_codes = codes_ref.get()
            
            code_found = False
            code_key = None
            code_data = None
            
            if all_codes:
                for key, data in all_codes.items():
                    if data and 'code' in data:
                        db_code_normalized = self.normalize_code(data['code'])
                        if db_code_normalized == normalized_entered:
                            code_found = True
                            code_key = key
                            code_data = data
                            break
            
            if not code_found:
                self.verify_btn.config(state='normal', text='Verify Device', bg='#3b82f6')
                messagebox.showerror("Invalid Code", "The verification code you entered is invalid.\n\nPlease check and try again.")
                return
            
            # Check if code is expired
            current_time = time.time() * 1000  # Convert to milliseconds
            if code_data.get('status') == 'expired' or code_data.get('expiresAt', 0) < current_time:
                self.verify_btn.config(state='normal', text='Verify Device', bg='#3b82f6')
                messagebox.showerror("Code Expired", "This verification code has expired.\n\nPlease generate a new code from the website.")
                return
            
            # Check if code is already used
            if code_data.get('used', False):
                self.verify_btn.config(state='normal', text='Verify Device', bg='#3b82f6')
                messagebox.showerror("Code Used", "This verification code has already been used.\n\nPlease generate a new code from the website.")
                return
            
            # Mark code as used
            codes_ref.child(code_key).update({
                'used': True,
                'usedAt': int(current_time),
                'status': 'verified'
            })
            
            # Generate device ID
            device_id = hashlib.sha256(f"{self.hwid}{time.time()}".encode()).hexdigest()[:16]
            
            # Register device in database
            devices_ref = db.reference('verified_devices')
            devices_ref.child(device_id).set({
                'hwid': self.hwid,
                'browserFingerprint': '',  # Will be set when user accesses website
                'verifiedAt': int(current_time),
                'status': 'active',
                'banned': False,
                'needsUsername': True,
                'verificationCode': code_data.get('code'),
                'platform': platform.system(),
                'lastLogin': int(current_time)
            })
            
            # Update verification code with device ID
            codes_ref.child(code_key).update({
                'deviceId': device_id
            })
            
            # Show success message
            messagebox.showinfo(
                "Verification Successful!",
                "Your device has been successfully verified and linked!\n\n"
                "Please return to the website to complete your account setup."
            )
            
            # Close app after success
            self.root.after(2000, self.root.destroy)
            
        except Exception as e:
            self.verify_btn.config(state='normal', text='Verify Device', bg='#3b82f6')
            messagebox.showerror("Verification Error", f"An error occurred during verification:\n\n{str(e)}\n\nPlease try again or contact support.")
            print(f"Verification error: {e}")

def main():
    """Main application entry point"""
    # Check if serviceAccountKey.json exists
    import os
    if not os.path.exists(SERVICE_ACCOUNT_PATH):
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Configuration Error",
            f"Firebase service account key not found!\n\n"
            f"Please ensure '{SERVICE_ACCOUNT_PATH}' is in the same directory as this application.\n\n"
            f"You can download this file from Firebase Console > Project Settings > Service Accounts."
        )
        return
    
    # Initialize Firebase
    if not initialize_firebase():
        return
    
    # Create and run application
    root = tk.Tk()
    app = LinkITApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
