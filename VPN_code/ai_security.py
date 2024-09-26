import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
from collections import deque
import time
import os
import string
import random

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    def __init__(self, contamination=0.1, window_size=100):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.window_size = window_size
        self.feature_window = deque(maxlen=window_size)
        self.last_anomaly_time = 0
        self.anomaly_threshold = 3  # Number of anomalies in a row to trigger an action

    def fit(self, data):
        scaled_data = self.scaler.fit_transform(data)
        self.model.fit(scaled_data)
        self.is_fitted = True
        logging.info("Anomaly detection model has been trained.")

    def predict(self, feature):
        if not self.is_fitted:
            raise ValueError("Model is not fitted yet. Call 'fit' with appropriate data first.")
        
        self.feature_window.append(feature)
        
        if len(self.feature_window) < self.window_size:
            return 0  # Not enough data to make a prediction
        
        window_data = np.array(self.feature_window)
        scaled_data = self.scaler.transform(window_data)
        predictions = self.model.predict(scaled_data)
        return 1 if predictions[-1] == -1 else 0

def extract_features(encrypted_chunks, duration):
    total_size = sum(len(chunk) for chunk in encrypted_chunks)
    num_chunks = len(encrypted_chunks)
    avg_chunk_size = total_size / num_chunks if num_chunks > 0 else 0
    entropy = calculate_entropy(encrypted_chunks)
    chunk_size_variance = np.var([len(chunk) for chunk in encrypted_chunks]) if num_chunks > 1 else 0
    
    features = np.array([
        total_size,
        num_chunks,
        avg_chunk_size,
        duration,
        entropy,
        chunk_size_variance
    ])
    return features.reshape(1, -1)

def calculate_entropy(encrypted_chunks):
    all_bytes = b''.join(encrypted_chunks)
    byte_counts = np.bincount(np.frombuffer(all_bytes, dtype=np.uint8), minlength=256)
    probabilities = byte_counts / len(all_bytes)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    return entropy

def check_anomaly(detector, encrypted_chunks, duration, avg_throughput):
    features = extract_features(encrypted_chunks, duration)
    is_anomaly = detector.predict(features[0])
    
    total_size = sum(len(chunk) for chunk in encrypted_chunks)
    current_throughput = total_size / duration if duration > 0 else 0
    
    if current_throughput > 5 * avg_throughput:
        is_anomaly = 1
    
    if is_anomaly:
        current_time = time.time()
        if current_time - detector.last_anomaly_time < 60:  # Check if last anomaly was within 60 seconds
            detector.anomaly_count += 1
        else:
            detector.anomaly_count = 1
        detector.last_anomaly_time = current_time

        if detector.anomaly_count >= detector.anomaly_threshold:
            take_action(features[0], current_throughput, avg_throughput)
        
        logging.warning(f"Anomaly detected: total_size={total_size}, num_chunks={len(encrypted_chunks)}, duration={duration}, throughput={current_throughput}")
    else:
        detector.anomaly_count = 0
    
    return is_anomaly

def take_action(features, current_throughput, avg_throughput):
    logging.warning("Taking action due to repeated anomalies")
    if current_throughput > 10 * avg_throughput:
        logging.warning("Extremely high throughput detected. Implementing rate limiting.")
        # Implement rate limiting logic here
    elif features[4] > 7.5:  # Check if entropy is very high
        logging.warning("Unusually high entropy detected. Flagging for further investigation.")
        # Implement flagging or alerting logic here
    else:
        logging.warning("Unspecified anomaly detected. Increasing monitoring frequency.")
        # Implement increased monitoring logic here

def adjust_chunks(encrypted_chunks, max_chunk_size):
    adjusted_chunks = []
    for chunk in encrypted_chunks:
        if len(chunk) > max_chunk_size:
            # Split the chunk into smaller pieces
            for i in range(0, len(chunk), max_chunk_size):
                adjusted_chunks.append(chunk[i:i+max_chunk_size])
        else:
            adjusted_chunks.append(chunk)
    return adjusted_chunks

def generate_secure_password(length=16):
    """Generate a secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Example usage
if __name__ == "__main__":
    # Simulated historical data
    historical_data = np.random.rand(1000, 6) * [1e6, 100, 1e4, 3600, 8, 1e6]  # Added entropy and variance
    
    detector = AnomalyDetector()
    detector.fit(historical_data)
    
    # Simulated encrypted chunks and duration
    normal_chunks = [os.urandom(1024) for _ in range(50)]
    anomalous_chunks = [os.urandom(1024*1024) for _ in range(5)]
    
    avg_throughput = 1e5  # bytes per second

    print("Normal connection anomaly:", check_anomaly(detector, normal_chunks, 10, avg_throughput))
    print("Anomalous connection anomaly:", check_anomaly(detector, anomalous_chunks, 1, avg_throughput))
    
    # Demonstrate chunk adjustment
    max_chunk_size = 512 * 1024  # 512 KB
    adjusted_chunks = adjust_chunks(anomalous_chunks, max_chunk_size)
    print(f"Original number of chunks: {len(anomalous_chunks)}")
    print(f"Adjusted number of chunks: {len(adjusted_chunks)}")