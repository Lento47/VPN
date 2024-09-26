from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureChannel:
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key[:32]  # Ensure key is 32 bytes (256 bits)
        self.chunk_size = 64 * 1024  # 64 KB chunks
        logging.debug(f"SecureChannel initialized with key: {self.key.hex()}")

    def encrypt_data(self, data):
        iv = os.urandom(12)  # 96-bit IV for GCM
        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        logging.debug(f"Encrypting data with IV: {iv.hex()}")

        # Chunking
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i+self.chunk_size]
            encrypted_chunk = encryptor.update(chunk)
            chunks.append(encrypted_chunk)

        # Finalize the encryption
        chunks.append(encryptor.finalize())

        result = iv + encryptor.tag + b''.join(chunks)
        logging.debug(f"Encrypted data (first 20 bytes): {result[:20].hex()}")
        return [result]

    def decrypt_data(self, encrypted_chunks):
        encrypted_data = encrypted_chunks[0]
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        logging.debug(f"Decrypting data with IV: {iv.hex()}, Tag: {tag.hex()}")

        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        # Chunking for decryption
        chunks = []
        for i in range(0, len(ciphertext), self.chunk_size):
            chunk = ciphertext[i:i+self.chunk_size]
            decrypted_chunk = decryptor.update(chunk)
            chunks.append(decrypted_chunk)

        # Finalize the decryption
        chunks.append(decryptor.finalize())

        result = b''.join(chunks)
        logging.debug(f"Decrypted data (first 20 bytes): {result[:20]}")
        return result

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            data = file.read()
        return self.encrypt_data(data)

    def decrypt_file(self, encrypted_data, output_file_path):
        decrypted_data = self.decrypt_data(encrypted_data)
        with open(output_file_path, 'wb') as file:
            file.write(decrypted_data)

# Example usage
if __name__ == "__main__":
    secure_channel = SecureChannel()

    # Test with string data
    original_data = b"This is a test message for encryption and decryption."
    encrypted = secure_channel.encrypt_data(original_data)
    decrypted = secure_channel.decrypt_data(encrypted)
    print(f"Original: {original_data}")
    print(f"Decrypted: {decrypted}")
    print(f"Encryption successful: {original_data == decrypted}")

    # Test with file
    with open("test_file.txt", "w") as f:
        f.write("This is a test file for encryption and decryption.")

    encrypted_file_data = secure_channel.encrypt_file("test_file.txt")
    secure_channel.decrypt_file(encrypted_file_data, "decrypted_test_file.txt")

    print("File encryption and decryption test completed. Check 'decrypted_test_file.txt'.")