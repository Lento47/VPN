import socket
import ssl
import os
import logging
import signal
import numpy as np
import threading
from ai_security import AnomalyDetector, check_anomaly, adjust_chunks
from encryption import SecureChannel
import select
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Shared secret and salt (in a real-world scenario, these should be securely exchanged)
SHARED_SECRET = b"your_secure_password"
SHARED_SALT = b"fixed_salt_for_testing"

class VPNServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cert_file = "server.crt"
        self.key_file = "server.key"
        self.secure_channel = None  # We'll create this per-client now
        self.sock = None
        self.running = False
        self.anomaly_detector = AnomalyDetector()
        self.train_anomaly_detector()
        
        # Derive the key using the shared secret and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SHARED_SALT,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(SHARED_SECRET)
        self.secure_channel = SecureChannel(key=key)
        
        self.max_chunk_size = 64 * 1024  # 64 KB, matching the SecureChannel chunk size
        self.avg_throughput = 1e5  # Initial average throughput (bytes per second)

    def train_anomaly_detector(self):
        historical_data = np.random.rand(1000, 6) * [1e6, 100, 1e4, 3600, 8, 1e6]
        self.anomaly_detector.fit(historical_data)

    def start(self):
        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            logging.error("Certificate files not found. Please generate them first.")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.sock.setblocking(False)
            logging.info(f"VPN Server listening on {self.host}:{self.port}")
            logging.info("Press Ctrl+C to stop the server.")

            self.running = True
            while self.running:
                try:
                    ready, _, _ = select.select([self.sock], [], [], 1.0)
                    if ready:
                        client, address = self.sock.accept()
                        logging.info(f"New connection from {address}")
                        client_thread = threading.Thread(target=self.handle_client, args=(client, context))
                        client_thread.start()
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting client connection: {e}")

    def handle_client(self, client_socket, context):
        with context.wrap_socket(client_socket, server_side=True) as secure_client:
            try:
                peername = secure_client.getpeername()
                logging.info(f"Handling client {peername}")
                
                # Receive the password from the client
                encrypted_password = secure_client.recv(1024)
                logging.debug(f"Received encrypted password from {peername}: {encrypted_password[:20].hex()}...")
                
                # Use a fixed key for the initial decryption
                initial_key = b'initial_key_for_password_decryption'[:32]  # Ensure 32 bytes
                temp_channel = SecureChannel(key=initial_key)
                password = temp_channel.decrypt_data([encrypted_password]).decode()
                logging.debug(f"Decrypted password from {peername}: {password}")
                
                # Now create the actual SecureChannel with the received password
                salt = b'fixed_salt_for_key_derivation'  # Use a fixed salt for now
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                self.secure_channel = SecureChannel(key=key)
                
                greeting = b"Hello from VPN Server!"
                encrypted_greeting = self.secure_channel.encrypt_data(greeting)
                secure_client.sendall(encrypted_greeting[0])
                logging.info(f"Sent encrypted greeting to {peername}: {encrypted_greeting[0][:20].hex()}...")
                
                start_time = time.time()
                total_bytes = 0
                while self.running:
                    try:
                        ready, _, _ = select.select([secure_client], [], [], 5.0)
                        if ready:
                            encrypted_data = secure_client.recv(self.max_chunk_size)
                            if not encrypted_data:
                                break
                            
                            total_bytes += len(encrypted_data)
                            duration = time.time() - start_time
                            
                            logging.info(f"Received encrypted data from {peername}: {encrypted_data[:20].hex()}...")
                            decrypted_data = self.secure_channel.decrypt_data([encrypted_data])
                            logging.info(f"Received from {peername}: {decrypted_data[:50]}...")

                            # Check for anomalies
                            is_anomaly = check_anomaly(self.anomaly_detector, [encrypted_data], duration, self.avg_throughput)
                            if is_anomaly:
                                logging.warning(f"Anomaly detected for {peername}")
                                # Note: adjust_chunks is not needed here as we're using fixed-size chunks

                            response = b"Acknowledged"
                            encrypted_response = self.secure_channel.encrypt_data(response)
                            
                            secure_client.sendall(encrypted_response[0])
                            logging.info(f"Sent encrypted response to {peername}: {encrypted_response[0][:20].hex()}...")

                            # Update average throughput
                            self.avg_throughput = 0.9 * self.avg_throughput + 0.1 * (total_bytes / duration)
                        else:
                            logging.debug(f"No data received from {peername} in the last 5 seconds")
                    except socket.error as e:
                        logging.error(f"Socket error with {peername}: {e}")
                        break
            except Exception as e:
                logging.error(f"Error in client communication with {peername}: {str(e)}", exc_info=True)
            finally:
                logging.info(f"Connection closed with {peername}")

    def stop(self):
        self.running = False
        logging.info("Stopping the server...")

def signal_handler(_, __):
    logging.info("Interrupt received, shutting down...")
    server.stop()

if __name__ == "__main__":
    server = VPNServer("0.0.0.0", 5000)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()