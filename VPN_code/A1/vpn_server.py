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

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Use the same fixed key as in the client
FIXED_KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for AES-256

class VPNServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cert_file = "server.crt"
        self.key_file = "server.key"
        self.sock = None
        self.running = False
        self.anomaly_detector = AnomalyDetector()
        self.train_anomaly_detector()
        self.secure_channel = SecureChannel(key=FIXED_KEY)
        self.max_chunk_size = 512 * 1024  # 512 KB

    def train_anomaly_detector(self):
        historical_data = np.random.rand(1000, 4) * [1e6, 100, 1e4, 3600]  # total_size, num_chunks, avg_chunk_size, duration
        self.anomaly_detector.fit(historical_data)

    def start(self):
        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            logging.error("Certificate files not found. Please generate them first.")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
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
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            if self.sock:
                self.sock.close()
            logging.info("Server shut down.")

    def handle_client(self, client_socket, context):
        client_socket.settimeout(10.0)  # Set a timeout for client socket operations
        with context.wrap_socket(client_socket, server_side=True) as secure_client:
            try:
                peername = secure_client.getpeername()
                logging.info(f"Handling client {peername}")
                
                greeting = b"Hello from VPN Server!"
                encrypted_greeting = self.secure_channel.encrypt_data(greeting)
                secure_client.sendall(encrypted_greeting[0])
                logging.info(f"Sent encrypted greeting to {peername}: {encrypted_greeting[0].hex()}")
                
                while self.running:
                    try:
                        ready, _, _ = select.select([secure_client], [], [], 5.0)
                        if ready:
                            encrypted_data = secure_client.recv(1024)
                            if not encrypted_data:
                                break
                            
                            logging.info(f"Received encrypted data from {peername}: {encrypted_data.hex()}")
                            try:
                                decrypted_data = self.secure_channel.decrypt_data([encrypted_data])
                                logging.info(f"Decrypted data from {peername}: {decrypted_data}")
                                logging.info(f"Received from {peername}: {decrypted_data.decode('utf-8', errors='replace')}")
                            except Exception as e:
                                logging.error(f"Failed to decrypt data from {peername}: {str(e)}")
                                continue

                            response = b"Acknowledged"
                            encrypted_response = self.secure_channel.encrypt_data(response)
                            
                            secure_client.sendall(encrypted_response[0])
                            logging.info(f"Sent encrypted response to {peername}: {encrypted_response[0].hex()}")
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