from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class SecureChannel:
    def __init__(self, key=None):
        self.key = key if key else os.urandom(32)  # 256-bit key
        self.chunk_size = 1024 * 1024  # 1MB chunks

    def encrypt_data(self, data):
        iv = os.urandom(16)  # 128-bit IV for AES
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()
        return [iv + ciphertext]

    def decrypt_data(self, encrypted_chunks):
        iv = encrypted_chunks[0][:16]
        ciphertext = encrypted_chunks[0][16:]

        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.CFB(iv),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()