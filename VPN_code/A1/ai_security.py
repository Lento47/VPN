import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging
import os  # Added for the example usage

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, data):
        scaled_data = self.scaler.fit_transform(data)
        self.model.fit(scaled_data)
        self.is_fitted = True
        logging.info("Anomaly detection model has been trained.")

    def predict(self, data):
        if not self.is_fitted:
            raise ValueError("Model is not fitted yet. Call 'fit' with appropriate data first.")
        
        scaled_data = self.scaler.transform(data)
        predictions = self.model.predict(scaled_data)
        return predictions

def extract_features(encrypted_chunks, duration):
    total_size = sum(len(chunk) for chunk in encrypted_chunks)
    num_chunks = len(encrypted_chunks)
    avg_chunk_size = total_size / num_chunks if num_chunks > 0 else 0
    
    features = np.array([
        total_size,
        num_chunks,
        avg_chunk_size,
        duration
    ])
    return features.reshape(1, -1)

def check_anomaly(detector, encrypted_chunks, duration, avg_throughput):
    features = extract_features(encrypted_chunks, duration)
    prediction = detector.predict(features)
    is_anomaly = prediction[0] == -1
    
    total_size = sum(len(chunk) for chunk in encrypted_chunks)
    current_throughput = total_size / duration if duration > 0 else 0
    
    if current_throughput > 5 * avg_throughput:
        is_anomaly = True
    
    if is_anomaly:
        logging.warning(f"Anomaly detected: total_size={total_size}, num_chunks={len(encrypted_chunks)}, duration={duration}")
    
    return is_anomaly

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

# Example usage
if __name__ == "__main__":
    # Simulated historical data
    historical_data = np.random.rand(1000, 4) * [1e6, 100, 1e4, 3600]  # total_size, num_chunks, avg_chunk_size, duration
    
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