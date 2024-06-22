import os
import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import shutil

USER_DIR = 'user'
KEY_SIZE = 32
SALT_SIZE = 16

def encrypt(data, password):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(data, password):
    data = base64.b64decode(data)
    salt, nonce, tag, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+16], data[SALT_SIZE+16:SALT_SIZE+32], data[SALT_SIZE+32:]
    key = PBKDF2(password, salt, dkLen=KEY_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

class EmailClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Mail Client")
        self.root.geometry("600x400")  # 设置窗口大小为600x400
        self.init_main_screen()

    def init_main_screen(self):
        self.clear_screen()
        
        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        login_button = tk.Button(frame, text="Login", command=self.init_login_screen)
        login_button.grid(row=0, column=0, padx=10, pady=10)
        register_button = tk.Button(frame, text="Register", command=self.init_register_screen)
        register_button.grid(row=0, column=1, padx=10, pady=10)
        manage_button = tk.Button(frame, text="Manage", command=self.init_manage_screen)
        manage_button.grid(row=1, column=0, columnspan=2, pady=10)

    def init_login_screen(self):
        self.clear_screen()
        
        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        tk.Label(frame, text="Select Email:").grid(row=0, column=0, padx=5, pady=5)
        self.email_combobox = ttk.Combobox(frame, width=47)
        self.email_combobox['values'] = self.get_user_emails()
        self.email_combobox.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(frame, show='*', width=50)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        login_button = tk.Button(frame, text="Login", command=self.login)
        login_button.grid(row=2, column=1, padx=5, pady=5)
        
        back_button = tk.Button(frame, text="Back", command=self.init_main_screen)
        back_button.grid(row=2, column=0, padx=5, pady=5)

    def init_register_screen(self):
        self.clear_screen()
        
        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(frame, text="Email:").grid(row=0, column=0, padx=5, pady=5)
        self.reg_email_entry = tk.Entry(frame, width=50)
        self.reg_email_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="SMTP Server:").grid(row=1, column=0, padx=5, pady=5)
        self.smtp_entry = tk.Entry(frame, width=50)
        self.smtp_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Port:").grid(row=2, column=0, padx=5, pady=5)
        self.port_entry = tk.Entry(frame, width=50)
        self.port_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(frame, text="Email Password:").grid(row=3, column=0, padx=5, pady=5)
        self.email_password_entry = tk.Entry(frame, show='*', width=50)
        self.email_password_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(frame, text="Local Password:").grid(row=4, column=0, padx=5, pady=5)
        self.local_password_entry = tk.Entry(frame, show='*', width=50)
        self.local_password_entry.grid(row=4, column=1, padx=5, pady=5)

        register_button = tk.Button(frame, text="Register", command=self.register)
        register_button.grid(row=5, column=1, padx=5, pady=5)
        
        back_button = tk.Button(frame, text="Back", command=self.init_main_screen)
        back_button.grid(row=5, column=0, padx=5, pady=5)

    def init_manage_screen(self):
        self.clear_screen()

        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(frame, text="Select Email to Delete:").grid(row=0, column=0, padx=5, pady=5)
        self.manage_combobox = ttk.Combobox(frame, width=47)
        self.manage_combobox['values'] = self.get_user_emails()
        self.manage_combobox.grid(row=0, column=1, padx=5, pady=5)

        delete_button = tk.Button(frame, text="Delete", command=self.delete_user)
        delete_button.grid(row=1, column=1, padx=5, pady=5)
        
        back_button = tk.Button(frame, text="Back", command=self.init_main_screen)
        back_button.grid(row=1, column=0, padx=5, pady=5)

    def init_email_screen(self, email, password, smtp_server, port):
        self.clear_screen()
        
        frame = tk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(frame, text="Receiver Email:").grid(row=0, column=0, padx=5, pady=5)
        self.receiver_entry = tk.Entry(frame, width=50)
        self.receiver_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Subject:").grid(row=1, column=0, padx=5, pady=5)
        self.subject_entry = tk.Entry(frame, width=50)
        self.subject_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Body:").grid(row=2, column=0, padx=5, pady=5)
        self.body_text = tk.Text(frame, height=10, width=50)
        self.body_text.grid(row=2, column=1, padx=5, pady=5)

        self.email = email
        self.password = password
        self.smtp_server = smtp_server
        self.port = port

        send_button = tk.Button(frame, text="Send", command=self.send_email)
        send_button.grid(row=3, column=1, padx=5, pady=5)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def get_user_emails(self):
        if not os.path.exists(USER_DIR):
            return []
        return [d for d in os.listdir(USER_DIR) if os.path.isdir(os.path.join(USER_DIR, d))]

    def login(self):
        email = self.email_combobox.get()
        local_password = self.password_entry.get()

        user_path = os.path.join(USER_DIR, email)
        if not os.path.exists(user_path):
            messagebox.showerror("Error", "User not found")
            return

        with open(os.path.join(user_path, 'main'), 'r') as f:
            encrypted_data = f.read()

        try:
            decrypted_data = decrypt(encrypted_data, local_password)
            smtp_server, port, email_password = decrypted_data.split('|')
            self.init_email_screen(email, email_password, smtp_server, port)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt data: {e}")

    def register(self):
        email = self.reg_email_entry.get()
        smtp_server = self.smtp_entry.get()
        port = self.port_entry.get()
        email_password = self.email_password_entry.get()
        local_password = self.local_password_entry.get()

        user_path = os.path.join(USER_DIR, email)
        if os.path.exists(user_path):
            messagebox.showerror("Error", "User already exists")
            return

        os.makedirs(user_path)

        data_to_encrypt = f"{smtp_server}|{port}|{email_password}"
        encrypted_data = encrypt(data_to_encrypt, local_password)

        with open(os.path.join(user_path, 'main'), 'w') as f:
            f.write(encrypted_data)

        messagebox.showinfo("Success", "User registered successfully")
        self.init_main_screen()

    def delete_user(self):
        email = self.manage_combobox.get()
        user_path = os.path.join(USER_DIR, email)
        if os.path.exists(user_path):
            shutil.rmtree(user_path)
            messagebox.showinfo("Success", f"User {email} deleted successfully")
            self.init_manage_screen()
        else:
            messagebox.showerror("Error", "User not found")

    def send_email(self):
        receiver = self.receiver_entry.get()
        subject = self.subject_entry.get()
        body = self.body_text.get("1.0", tk.END)

        msg = MIMEMultipart()
        msg['From'] = self.email
        msg['To'] = receiver
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, int(self.port)) as server:
                server.starttls()
                server.login(self.email, self.password)
                server.sendmail(self.email, receiver, msg.as_string())
            messagebox.showinfo("Success", "Email sent successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {e}")

if __name__ == "__main__":
    if not os.path.exists(USER_DIR):
        os.makedirs(USER_DIR)
    
    root = tk.Tk()
    app = EmailClient(root)
    root.mainloop()
