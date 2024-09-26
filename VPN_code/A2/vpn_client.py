import tkinter as tk
from tkinter import ttk, messagebox
import socket
import ssl
import threading
import time
import logging
from encryption import SecureChannel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
from ai_security import generate_secure_password

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class VPNClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("VPN Client")
        master.geometry("300x400")  # Increased height for password display

        self.server_host = tk.StringVar(value="localhost")
        self.server_port = tk.IntVar(value=5000)
        self.connection_status = tk.StringVar(value="Disconnected")
        self.bytes_sent = tk.IntVar(value=0)
        self.bytes_received = tk.IntVar(value=0)
        self.password = tk.StringVar(value="")
                
        self.secure_channel = None
        self.secure_sock = None
        self.running = False

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.master, text="Server Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(self.master, textvariable=self.server_host).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.master, text="Server Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(self.master, textvariable=self.server_port).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.master, text="Password:").grid(row=6, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.master, textvariable=self.password).grid(row=6, column=1, padx=5, pady=5, sticky="w")

        self.connect_button = ttk.Button(self.master, text="Connect", command=self.connect)
        self.connect_button.grid(row=2, column=0, pady=10)

        self.disconnect_button = ttk.Button(self.master, text="Disconnect", command=self.disconnect, state="disabled")
        self.disconnect_button.grid(row=2, column=1, pady=10)

        ttk.Label(self.master, text="Status:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.master, textvariable=self.connection_status).grid(row=3, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.master, text="Bytes Sent:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.master, textvariable=self.bytes_sent).grid(row=4, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.master, text="Bytes Received:").grid(row=5, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.master, textvariable=self.bytes_received).grid(row=5, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.master, text="Password:").grid(row=6, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.master, textvariable=self.password).grid(row=6, column=1, padx=5, pady=5, sticky="w")

        self.reset_button = ttk.Button(self.master, text="Reset Counters", command=self.reset_counters)
        self.reset_button.grid(row=7, column=0, columnspan=2, pady=10)


    def connect(self):
        self.connection_status.set("Connecting...")
        self.connect_button.config(state="disabled")
        self.disconnect_button.config(state="disabled")

        # Generate a new password for each connection
        new_password = generate_secure_password()
        self.password.set(new_password)

        # Use the same fixed salt as the server
        salt = b'fixed_salt_for_key_derivation'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(new_password.encode())
        self.secure_channel = SecureChannel(key=key)

        threading.Thread(target=self._connect_thread, daemon=True).start()

    def _connect_thread(self):
        try:
            logging.info(f"Attempting to connect to {self.server_host.get()}:{self.server_port.get()}")
            
            with socket.create_connection((self.server_host.get(), self.server_port.get()), timeout=10) as sock:
                logging.info("TCP connection established.")

                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # Only for testing, not secure for production
                
                with context.wrap_socket(sock, server_hostname=self.server_host.get()) as self.secure_sock:
                    logging.info("SSL handshake completed.")

                    # Use a fixed key for the initial encryption of the password
                    initial_key = b'initial_key_for_password_decryption'[:32]  # Ensure 32 bytes
                    temp_channel = SecureChannel(key=initial_key)
                    encrypted_password = temp_channel.encrypt_data(self.password.get().encode())
                    self.secure_sock.sendall(encrypted_password[0])
                    logging.info("Sent encrypted password to server.")

                    # Receive and decrypt the greeting
                    encrypted_greeting = self.secure_sock.recv(1024)
                    logging.info(f"Received encrypted greeting: {encrypted_greeting.hex()}")
                    greeting = self.secure_channel.decrypt_data([encrypted_greeting])
                    logging.info(f"Received greeting: {greeting.decode('utf-8', errors='replace')}")

                    self.running = True
                    while self.running:
                        self.send_heartbeat()
                        time.sleep(5)

        except Exception as e:
            logging.error(f"Connection error: {str(e)}", exc_info=True)
            self.connection_status.set("Error")
        finally:
            self.master.after(0, self.connect_button.config, {"state": "normal"})
            self.master.after(0, self.disconnect_button.config, {"state": "disabled"})
            self.running = False

    def send_heartbeat(self):
        try:
            message = "Heartbeat"
            encrypted_message = self.secure_channel.encrypt_data(message.encode())
            self.secure_sock.sendall(encrypted_message[0])
            self.bytes_sent.set(self.bytes_sent.get() + len(encrypted_message[0]))
            logging.info(f"Sent encrypted heartbeat: {encrypted_message[0][:20].hex()}...")

            encrypted_response = self.secure_sock.recv(1024)
            logging.info(f"Received encrypted response: {encrypted_response[:20].hex()}...")
            response = self.secure_channel.decrypt_data([encrypted_response])
            self.bytes_received.set(self.bytes_received.get() + len(encrypted_response))
            logging.info(f"Heartbeat response: {response.decode('utf-8', errors='replace')}")
        except Exception as e:
            logging.error(f"Heartbeat Error: {str(e)}")
            self.disconnect()

    def disconnect(self):
        self.running = False
        if self.secure_sock:
            try:
                self.secure_sock.close()
            except:
                pass
            self.secure_sock = None
        self.connection_status.set("Disconnected")
        self.connect_button.config(state="normal")
        self.disconnect_button.config(state="disabled")
        logging.info("Disconnected from VPN server.")

    def reset_counters(self):
        self.bytes_sent.set(0)
        self.bytes_received.set(0)

if __name__ == "__main__":
    root = tk.Tk()
    client_gui = VPNClientGUI(root)
    root.mainloop()