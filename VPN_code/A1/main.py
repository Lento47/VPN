# vpn_client.py
import socket

class VPNClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port

    def connect(self):
        with socket.create_connection((self.server_host, self.server_port)) as sock:
            print(f"Connected to VPN server at {self.server_host}:{self.server_port}")
            self.handle_connection(sock)

    def handle_connection(self, sock):
        data = sock.recv(1024)
        print(f"Received: {data.decode()}")