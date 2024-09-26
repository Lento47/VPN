import tkinter as tk
from tkinter import ttk, messagebox
import socket
import ssl
import threading
import time
import logging
from encryption import SecureChannel

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Use a fixed key for both client and server
FIXED_KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for AES-256

class VPNClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("VPN Client")
        master.geometry("300x330")  # Slightly increased height for the new button

        self.server_host = tk.StringVar(value="localhost")
        self.server_port = tk.IntVar(value=5000)
        self.connection_status = tk.StringVar(value="Disconnected")
        self.bytes_sent = tk.IntVar(value=0)
        self.bytes_received = tk.IntVar(value=0)
        self.secure_channel = SecureChannel()
        self.secure_channel = SecureChannel(key=FIXED_KEY)

        self.secure_sock = None
        self.running = False

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.master, text="Server Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(self.master, textvariable=self.server_host).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.master, text="Server Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(self.master, textvariable=self.server_port).grid(row=1, column=1, padx=5, pady=5)

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

        self.reset_button = ttk.Button(self.master, text="Reset Counters", command=self.reset_counters)
        self.reset_button.grid(row=6, column=0, columnspan=2, pady=10)


    def connect(self):
        self.connection_status.set("Connecting...")
        self.connect_button.config(state="disabled")
        self.disconnect_button.config(state="disabled")

        def connection_thread():
            try:
                logging.info(f"Attempting to connect to {self.server_host.get()}:{self.server_port.get()}")
                
                sock = socket.create_connection((self.server_host.get(), self.server_port.get()), timeout=10)
                logging.info("TCP connection established.")

                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # Only for testing, not secure for production
                
                self.secure_sock = context.wrap_socket(sock, server_hostname=self.server_host.get())
                logging.info("SSL handshake completed.")

                # Receive and decrypt the greeting
                encrypted_greeting = self.secure_sock.recv(1024)
                logging.info(f"Received encrypted greeting: {encrypted_greeting.hex()}")
                try:
                    greeting = self.secure_channel.decrypt_data([encrypted_greeting])
                    logging.info(f"Decrypted greeting: {greeting}")
                    logging.info(f"Received greeting: {greeting.decode('utf-8', errors='replace')}")
                except Exception as e:
                    logging.error(f"Failed to decrypt greeting: {str(e)}")
                    raise

                self.connection_status.set("Connected")
                self.disconnect_button.config(state="normal")
                logging.info("Successfully connected to VPN server.")

                self.running = True
                while self.running:
                    self.send_heartbeat()
                    time.sleep(5)

            except Exception as e:
                logging.error(f"Connection error: {str(e)}", exc_info=True)
                self.connection_status.set("Error")

            finally:
                self.connect_button.config(state="normal")
                self.disconnect_button.config(state="disabled")
                self.running = False

        threading.Thread(target=connection_thread, daemon=True).start()

    def send_heartbeat(self):
        try:
            message = "Heartbeat"
            encrypted_message = self.secure_channel.encrypt_data(message.encode())
            self.secure_sock.sendall(encrypted_message[0])
            self.bytes_sent.set(self.bytes_sent.get() + len(encrypted_message[0]))
            logging.info(f"Sent encrypted heartbeat: {encrypted_message[0].hex()}")

            encrypted_response = self.secure_sock.recv(1024)
            logging.info(f"Received encrypted response: {encrypted_response.hex()}")
            try:
                response = self.secure_channel.decrypt_data([encrypted_response])
                self.bytes_received.set(self.bytes_received.get() + len(encrypted_response))
                logging.info(f"Heartbeat response: {response.decode('utf-8', errors='replace')}")
            except Exception as e:
                logging.error(f"Failed to decrypt heartbeat response: {str(e)}")
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