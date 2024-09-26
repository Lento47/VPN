# vpn_server.py
import socket

class VPNServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"VPN Server listening on {self.host}:{self.port}")

            while True:
                client, address = sock.accept()
                print(f"Connection from {address}")
                self.handle_client(client)

    def handle_client(self, client_socket):
        with client_socket:
            client_socket.sendall(b"Hello from VPN Server!")
            