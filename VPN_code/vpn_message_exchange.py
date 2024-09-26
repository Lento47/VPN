import os
from encryption import SecureChannel
from ai_security import AnomalyDetector, check_anomaly, adjust_chunks
import numpy as np
import time

# Initialize SecureChannel and AnomalyDetector
secure_channel = SecureChannel()
anomaly_detector = AnomalyDetector()

# Train the anomaly detector with some sample data
historical_data = np.random.rand(1000, 4) * [1e6, 100, 1e4, 3600]
anomaly_detector.fit(historical_data)

def send_encrypted_message(message, phase):
    encrypted_chunks = secure_channel.encrypt_data(message.encode())
    
    # Simulate network transmission
    start_time = time.time()
    time.sleep(len(message) / 1000)  # Simulate network delay
    duration = time.time() - start_time
    
    # Check for anomalies
    is_anomaly = check_anomaly(anomaly_detector, encrypted_chunks, duration, 1e5)
    
    if is_anomaly:
        print(f"Anomaly detected in Phase {phase} message. Adjusting chunks...")
        encrypted_chunks = adjust_chunks(encrypted_chunks, 512 * 1024)
    
    # In a real scenario, you would send these chunks over the network
    print(f"Sending {len(encrypted_chunks)} encrypted chunks for Phase {phase}")
    
    # Simulate receiving and decrypting
    decrypted_data = secure_channel.decrypt_data(encrypted_chunks)
    print(f"Decrypted message: {decrypted_data.decode()}")
    print()

# Phase 1: Policies
policies = [
    "1. All traffic must be encrypted",
    "2. No logging of user activities",
    "3. Automatic disconnection after 30 minutes of inactivity"
]

for i, policy in enumerate(policies, 1):
    send_encrypted_message(policy, f"1 (Policy {i})")

# Phase 2: Tunnel mode and unique string
tunnel_mode = "IPsec Transport Mode"
unique_string = "AI-Enhanced-VPN-" + os.urandom(8).hex()

send_encrypted_message(f"Tunnel Mode: {tunnel_mode}", "2 (Tunnel Mode)")
send_encrypted_message(f"Unique String: {unique_string}", "2 (Unique String)")
send_encrypted_message("End of Phase 2", "2 (Completion)")