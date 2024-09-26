
import socket
import ssl
from encryption import SecureChannel
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def test_client():
    host = 'localhost'
    port = 5000

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # For testing only, don't use in production

    secure_channel = SecureChannel()

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                logging.info(f"Connected to {host}:{port}")

                # Receive and decrypt greeting
                encrypted_greeting = secure_sock.recv(1024)
                logging.info(f"Encrypted greeting length: {len(encrypted_greeting)}")
                if len(encrypted_greeting) > 0:
                    greeting = secure_channel.decrypt_chunk(encrypted_greeting)
                    logging.info(f"Received greeting: {greeting.decode()}")
                else:
                    logging.error("Received empty encrypted greeting!")

                # Send an encrypted message
                message = "Hello from client!"
                encrypted_message = secure_channel.encrypt_data(message.encode())[0]
                logging.info(f"Sending encrypted message: {encrypted_message.hex()}")
                if len(encrypted_message) > 0:
                    secure_sock.sendall(encrypted_message)
                    logging.info(f"Encrypted message length: {len(encrypted_message)}")
                else:
                    logging.error("Encrypted message is empty!")

                # Receive and decrypt response
                encrypted_response = secure_sock.recv(1024)
                logging.info(f"Encrypted response length: {len(encrypted_response)}")
                if len(encrypted_response) > 0:
                    response = secure_channel.decrypt_chunk(encrypted_response)
                    logging.info(f"Received response: {response.decode()}")
                else:
                    logging.error("Received empty encrypted response!")

    except Exception as e:
        logging.error(f"Error in client: {e}")

if __name__ == "__main__":
    test_client()
