import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import argparse
import os
import matplotlib.pyplot as plt
import seaborn as sns
import joblib 
import time
import platform
import base64
import io
from flask import Flask, request, redirect, jsonify, Response, send_file
from threading import Thread
import json
from flask_cors import CORS  # Add CORS support for Next.js frontend

# Revised Scapy import handling
try:
    import scapy.all as scapy
    sniff = scapy.sniff
    IP, TCP, UDP = scapy.IP, scapy.TCP, scapy.UDP
    conf = scapy.conf
    L3RawSocket = getattr(scapy, "L3RawSocket", None)
    from scapy.utils import wrpcap
    if L3RawSocket is None:
        print("Warning: Scapy L3RawSocket not found, live mode on Windows may still work at L2.")
except Exception as e:
    print(f"Error importing scapy: {e}")
    print("  1) Ensure the Scapy Python package is installed: pip install scapy")
    if platform.system() == "Windows":
        print("  2) Install Npcap (with WinPcap API-compatible Mode) from https://npcap.org/")
    print("Live capture mode will not be available.")
    sniff = None

# Global variables
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enable CORS for all routes, explicitly allowing all origins

@app.after_request
def add_permissive_csp_headers(response):
    # WARNING: This sets a very permissive Content Security Policy.
    # It is intended for development troubleshooting ONLY and should NOT be used in production.
    # This attempts to allow inline scripts and scripts from any source.
    # It may conflict with or be overridden by CSPs set by your frontend framework
    # or reverse proxy, especially if they use nonces.
    # The errors you're seeing (related to 'nonce-...') are often due to browser extensions
    # injecting scripts that don't have the required nonce set by the frontend.
    # Modifying the frontend's CSP generation or using a clean browser profile for development
    # are often more effective solutions for such nonce-related CSP issues.
    
    # Set a very broad policy for scripts.
    # You might need to adjust other directives (default-src, style-src, etc.) if other CSP errors appear.
    csp_value = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' *; connect-src 'self' *;"
    response.headers['Content-Security-Policy'] = csp_value
    return response

live_packet_data_batch = []
LOADED_FEATURE_COLUMNS_GLOBAL = []
# Variables for live capture
live_capture_active = False
live_capture_thread = None
live_results = []
model = None
classes = None
loaded_feature_columns = None
model_expected_num_features = None
scaler = None

# Add a dictionary for configurable confidence thresholds per attack type
# Higher thresholds mean fewer false positives but might increase false negatives
CONFIDENCE_THRESHOLDS = {
    'Normal Traffic': 0.5,  # Lower threshold for normal traffic
    'DoS': 0.95,           # Higher threshold for DoS since it has false positives
    'DDoS': 0.9,
    'Port Scan': 0.9,
    'Brute Force': 0.9,
    'default': 0.85        # Default threshold for other attack types
}

def extract_features_from_live_packets(packet_list, feature_names):
    """
    Extract features from a list of captured Scapy packets.
    Groups packets into flows and calculates statistics to match the expected features.
    
    Args:
        packet_list (list): A list of Scapy packet objects.
        feature_names (list): A list of feature names the model expects.
    
    Returns:
        pd.DataFrame: DataFrame with extracted features matching model expectations.
    """
    print(f"Extracting features for {len(packet_list)} packets...")
    if not packet_list:
        return pd.DataFrame(columns=feature_names)
    
    # Group packets into flows
    flows = {}  # Dictionary to store flows: (src_ip, src_port, dst_ip, dst_port, proto) -> [packets]
    
    # First pass: group packets into flows
    for packet in packet_list:
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Handle TCP packets
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                # Create bidirectional flow key (smaller IP first to ensure consistency)
                if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                    flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
                    direction = 'forward'
                else:
                    flow_key = (dst_ip, dst_port, src_ip, src_port, proto)
                    direction = 'backward'
                
            # Handle UDP packets
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                # Create bidirectional flow key (smaller IP first)
                if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                    flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
                    direction = 'forward'
                else:
                    flow_key = (dst_ip, dst_port, src_ip, src_port, proto)
                    direction = 'backward'
            
            # Other protocols (ICMP etc.)
            else:
                src_port = 0
                dst_port = 0
                if src_ip < dst_ip:
                    flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
                    direction = 'forward'
                else:
                    flow_key = (dst_ip, dst_port, src_ip, src_port, proto)
                    direction = 'backward'
            
            # Add packet to flow
            if flow_key not in flows:
                flows[flow_key] = {'packets': [], 'fwd_packets': [], 'bwd_packets': []}
            
            flows[flow_key]['packets'].append(packet)
            
            # Add to directional lists
            if direction == 'forward':
                flows[flow_key]['fwd_packets'].append(packet)
            else:
                flows[flow_key]['bwd_packets'].append(packet)
    
    # Second pass: extract features from each flow
    processed_data = []
    flow_details = []  # Store flow details for logging/debugging
    
    for flow_key, flow_data in flows.items():
        try:
            src_ip, src_port, dst_ip, dst_port, proto = flow_key
            packets = flow_data['packets']
            fwd_packets = flow_data['fwd_packets']
            bwd_packets = flow_data['bwd_packets']
            
            if not packets:
                continue
            
            # Store basic flow info for debugging
            flow_info = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip, 
                'dst_port': dst_port,
                'protocol': 'TCP' if proto == 6 else 'UDP' if proto == 17 else str(proto),
                'packet_count': len(packets),
                'fwd_packet_count': len(fwd_packets),
                'bwd_packet_count': len(bwd_packets)
            }
                
            # Get timestamps for all packets
            timestamps = [float(packet.time) for packet in packets if hasattr(packet, 'time')]
            if not timestamps:
                continue
                
            # Calculate time-based features
            flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001  # Avoid division by zero
            flow_info['duration'] = flow_duration
            
            # Initialize features dictionary with zeros for all expected features
            features = {feature: 0.0 for feature in feature_names}
            
            # Basic flow features
            features['Total Fwd Packets'] = len(fwd_packets)
            features['Total Backward Packets'] = len(bwd_packets)
            
            # Calculate total packet lengths and store in flow_info
            fwd_total_len = sum(len(p) for p in fwd_packets)
            bwd_total_len = sum(len(p) for p in bwd_packets)
            features['Total Length of Fwd Packets'] = fwd_total_len
            features['Total Length of Bwd Packets'] = bwd_total_len
            flow_info['fwd_bytes'] = fwd_total_len
            flow_info['bwd_bytes'] = bwd_total_len
            
            # Calculate packet lengths
            fwd_packet_lengths = [len(p) for p in fwd_packets]
            bwd_packet_lengths = [len(p) for p in bwd_packets]
            all_packet_lengths = fwd_packet_lengths + bwd_packet_lengths
            
            # Packet length statistics - with additional DoS detection improvements
            if fwd_packet_lengths:
                features['Fwd Packet Length Max'] = max(fwd_packet_lengths)
                features['Fwd Packet Length Min'] = min(fwd_packet_lengths)
                features['Fwd Packet Length Mean'] = np.mean(fwd_packet_lengths)
                features['Fwd Packet Length Std'] = np.std(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0
                
                # Store in flow_info
                flow_info['fwd_pkt_len_mean'] = features['Fwd Packet Length Mean']
                flow_info['fwd_pkt_len_std'] = features['Fwd Packet Length Std']
            
            if bwd_packet_lengths:
                features['Bwd Packet Length Max'] = max(bwd_packet_lengths)
                features['Bwd Packet Length Min'] = min(bwd_packet_lengths)
                features['Bwd Packet Length Mean'] = np.mean(bwd_packet_lengths)
                features['Bwd Packet Length Std'] = np.std(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0
                
                # Store in flow_info
                flow_info['bwd_pkt_len_mean'] = features['Bwd Packet Length Mean']
                flow_info['bwd_pkt_len_std'] = features['Bwd Packet Length Std']
            
            # Calculate flow rates - important for DoS detection
            if all_packet_lengths:
                flow_bytes_sec = sum(all_packet_lengths) / flow_duration if flow_duration > 0 else 0
                flow_pkts_sec = len(all_packet_lengths) / flow_duration if flow_duration > 0 else 0
                features['Flow Bytes/s'] = flow_bytes_sec
                features['Flow Packets/s'] = flow_pkts_sec
                
                # Store rates in flow_info - useful for DoS pattern recognition
                flow_info['bytes_per_sec'] = flow_bytes_sec
                flow_info['pkts_per_sec'] = flow_pkts_sec
                
                # Add an additional check for potential DoS patterns
                # False positive DoS often has high packet rates but not extreme
                if flow_pkts_sec > 1000:  # High packet rate
                    flow_info['high_pkt_rate'] = True
                    
                # Features that help distinguish legitimate high-traffic from DoS
                if len(fwd_packets) > 0 and len(bwd_packets) > 0:
                    flow_info['has_bidirectional'] = True
                    # Legitimate traffic often has balanced replies
                    reply_ratio = len(bwd_packets) / len(fwd_packets)
                    flow_info['reply_ratio'] = reply_ratio
            
            # Handle TCP-specific features
            if proto == 6:  # TCP protocol
                # Count TCP flags
                syn_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)  # SYN flag
                fin_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x01)  # FIN flag
                rst_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x04)  # RST flag
                psh_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x08)  # PSH flag
                ack_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x10)  # ACK flag
                urg_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x20)  # URG flag
                
                if 'SYN Flag Count' in feature_names: features['SYN Flag Count'] = syn_count
                if 'FIN Flag Count' in feature_names: features['FIN Flag Count'] = fin_count
                if 'RST Flag Count' in feature_names: features['RST Flag Count'] = rst_count
                if 'PSH Flag Count' in feature_names: features['PSH Flag Count'] = psh_count
                if 'ACK Flag Count' in feature_names: features['ACK Flag Count'] = ack_count
                if 'URG Flag Count' in feature_names: features['URG Flag Count'] = urg_count
                
                # Add tracking of flag combinations for DoS detection
                if 'SYN Flag Count' in feature_names and 'ACK Flag Count' in feature_names:
                    syn_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)
                    ack_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x10)
                    
                    # SYN flood typically has high SYN to ACK ratio
                    if syn_count > 0:
                        syn_ack_ratio = syn_count / (ack_count + 0.1)  # Avoid div by zero
                        flow_info['syn_ack_ratio'] = syn_ack_ratio
                        
                        # High SYN count with low ACKs often indicates SYN flood DoS
                        if syn_count > 10 and syn_ack_ratio > 5:
                            flow_info['potential_syn_flood'] = True
            
            # Calculate inter-arrival times - important for traffic pattern analysis
            if len(timestamps) > 1:
                inter_arrival_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                features['Flow IAT Mean'] = np.mean(inter_arrival_times)
                features['Flow IAT Std'] = np.std(inter_arrival_times)
                features['Flow IAT Max'] = max(inter_arrival_times)
                features['Flow IAT Min'] = min(inter_arrival_times)
                
                # Add to flow_info
                flow_info['iat_mean'] = features['Flow IAT Mean']
                flow_info['iat_std'] = features['Flow IAT Std']
                
                # DoS often shows very regular timing - low std deviation in inter-arrival times
                if features['Flow IAT Std'] < 0.001 and len(packets) > 10:
                    flow_info['regular_timing'] = True

            # Ensure all expected features are present
            for feature in feature_names:
                if feature not in features:
                    features[feature] = 0.0
            
            # Store the flow details for logging
            flow_details.append(flow_info)
            processed_data.append(features)
            
        except Exception as e:
            print(f"Error processing flow {flow_key}: {e}")
            continue
    
    if not processed_data:
        print("No flows could be processed.")
        return pd.DataFrame(columns=feature_names)
    
    # Create DataFrame and ensure columns match expected feature names
    df = pd.DataFrame(processed_data)
    
    # Only include columns that are in feature_names and in the correct order
    result_df = pd.DataFrame(columns=feature_names)
    for col in feature_names:
        if col in df.columns:
            result_df[col] = df[col]
        else:
            result_df[col] = 0.0  # Default value if feature couldn't be calculated
    
    # Log detailed flow information for debugging false positives
    if flow_details:
        print(f"Flow details for debugging (showing up to 3):")
        for i, fd in enumerate(flow_details[:3]):
            print(f"Flow {i+1}: {fd['src_ip']}:{fd['src_port']} -> {fd['dst_ip']}:{fd['dst_port']} ({fd['protocol']})")
            print(f"  Packets: {fd['packet_count']} ({fd['fwd_packet_count']} fwd, {fd['bwd_packet_count']} bwd)")
            if 'bytes_per_sec' in fd:
                print(f"  Traffic rate: {fd['bytes_per_sec']:.2f} B/s, {fd['pkts_per_sec']:.2f} pkts/s")
            if 'potential_syn_flood' in fd and fd['potential_syn_flood']:
                print(f"  NOTICE: Potential SYN flood pattern detected")
            if 'high_pkt_rate' in fd and fd['high_pkt_rate']:
                print(f"  NOTICE: Unusually high packet rate")
    
    print(f"Successfully extracted features for {len(result_df)} flows")
    return result_df

def packet_handler(packet):
    """
    Handles each captured packet. Appends to a global batch.
    """
    global live_packet_data_batch
    live_packet_data_batch.append(packet)
    
def load_model_and_metadata():
    """
    Load the trained model and necessary metadata for inference
    """
    global LOADED_FEATURE_COLUMNS_GLOBAL # To store loaded feature names
    # Load the model
    model_path = 'malicious_traffic_cnn_model.keras'
    if not os.path.exists(model_path):
        print(f"Error: Model file '{model_path}' not found.")
        return None, None, None, None, None # Added None for scaler
    
    model = tf.keras.models.load_model(model_path)
    
    # Load label encoder classes
    encoder_classes_path = 'label_encoder_classes.npy'
    if not os.path.exists(encoder_classes_path):
        print(f"Error: Label encoder classes file '{encoder_classes_path}' not found.")
        return model, None, None, None, None # Added None for scaler
    
    classes = np.load(encoder_classes_path, allow_pickle=True)

    # Load feature columns used during training
    feature_columns_path = 'feature_columns.npy'
    if not os.path.exists(feature_columns_path):
        print(f"Error: Feature columns file '{feature_columns_path}' not found.")
        return model, classes, None, None, None # Added None for scaler
    
    loaded_feature_columns = np.load(feature_columns_path, allow_pickle=True).tolist()

    # Load the scaler
    scaler_path = 'scaler.joblib'
    if not os.path.exists(scaler_path):
        print(f"Error: Scaler file '{scaler_path}' not found.")
        return model, classes, loaded_feature_columns, None, None # Added None for scaler
    
    scaler = joblib.load(scaler_path)

    # Determine expected number of features from model's input shape
    expected_num_features_from_model = None
    try:
        expected_num_features_from_model = model.input_shape[1]
        if len(loaded_feature_columns) != expected_num_features_from_model:
            print(f"Warning: The number of loaded feature columns ({len(loaded_feature_columns)}) "
                  f"does not match the model's expected input features ({expected_num_features_from_model}). "
                  "This might indicate a mismatch between training and inference setup.")
    except Exception as e:
        print(f"Could not determine expected number of features from model: {e}")
    
    LOADED_FEATURE_COLUMNS_GLOBAL = loaded_feature_columns # Store for packet_handler/feature_extraction
    
    return model, classes, loaded_feature_columns, expected_num_features_from_model, scaler # Return scaler

def preprocess_data(data_input, expected_features_list, model_expected_num_features, scaler, is_live_data=False):
    """
    Preprocess input data for model inference.
    Can handle a file path (CSV) or a DataFrame (for live data).
    """
    try:
        if is_live_data:
            if not isinstance(data_input, pd.DataFrame):
                print("Error: Live data input must be a Pandas DataFrame.")
                return None, None
            data = data_input
        elif data_input.endswith('.csv'):
            data = pd.read_csv(data_input)
        else:
            print("Unsupported file format or input type. Please provide a CSV file or a DataFrame for live data.")
            return None, None
        
        if data.empty:
            print("Input data is empty. Skipping preprocessing.")
            return None, None

        # Verify and select expected feature columns
        missing_cols = [col for col in expected_features_list if col not in data.columns]
        if missing_cols:
            print(f"Error: The following expected feature columns are missing in the input data: {missing_cols}")
            print(f"Expected columns based on training: {expected_features_list}")
            return None, None
        
        # Ensure the number of features matches what the model expects, if known
        if model_expected_num_features is not None and len(expected_features_list) != model_expected_num_features:
            print(f"Error: Number of provided features in input CSV after selection ({len(expected_features_list)}) "
                  f"does not match model's expected input features ({model_expected_num_features}).")
            print("This usually means the 'feature_columns.npy' or the model is not from the same training run.")
            return None, None

        X = data[expected_features_list].values
        
        # Scale the features using the loaded scaler
        # IMPORTANT: Use transform, NOT fit_transform, on new data.
        if scaler is None:
            print("Error: Scaler was not loaded. Cannot preprocess data.")
            return None, None
        X_scaled = scaler.transform(X)
        
        # Reshape for CNN input: (samples, timesteps, features)
        # Here, timesteps is effectively the number of features, and features per timestep is 1.
        X_cnn = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)
        
        return X_cnn, data[expected_features_list] # Return only the selected features for consistency
    
    except Exception as e:
        print(f"Error preprocessing data: {str(e)}")
        return None, None

def predict_malicious_traffic(model, data, classes, apply_thresholds=True):
    """
    Make predictions on input data with improved confidence handling
    """
    # Get raw prediction probabilities
    pred_probs = model.predict(data)
    
    # Get the predicted class indices and raw predictions
    pred_classes = np.argmax(pred_probs, axis=1)
    predictions = classes[pred_classes]
    confidence = np.max(pred_probs, axis=1)
    
    # Apply confidence thresholds if requested
    if apply_thresholds:
        # Create a copy to avoid modifying the originals
        adjusted_predictions = predictions.copy()
        
        for i, (pred, conf) in enumerate(zip(predictions, confidence)):
            # Get threshold for this prediction type (use default if not specified)
            threshold = CONFIDENCE_THRESHOLDS.get(pred, CONFIDENCE_THRESHOLDS['default'])
            
            # If confidence is below threshold and not normal traffic, mark as uncertain
            if conf < threshold and pred != 'Normal Traffic':
                # Find the confidence for Normal Traffic
                normal_idx = np.where(classes == 'Normal Traffic')[0][0]
                normal_conf = pred_probs[i, normal_idx]
                
                # If the Normal Traffic confidence is reasonable, use it instead
                if normal_conf > 0.3:
                    adjusted_predictions[i] = 'Normal Traffic'
                    confidence[i] = normal_conf
        
        return adjusted_predictions, confidence, pred_probs
    
    # Return raw predictions if thresholds not applied
    return predictions, confidence, pred_probs

def get_network_interfaces():
    """
    Return a list of available network interfaces
    """
    interfaces = []
    try:
        if sniff is not None:
            if platform.system() == "Windows":
                try:
                    # First try the standard Scapy function
                    interfaces = scapy.get_windows_if_list()
                    interfaces = [{'name': i['name'], 'description': i['description']} for i in interfaces]
                except AttributeError:
                    try:
                        # Try to import directly from scapy.arch.windows
                        from scapy.arch.windows import get_windows_if_list
                        interfaces = get_windows_if_list()
                        interfaces = [{'name': i['name'], 'description': i['description']} for i in interfaces]
                    except (ImportError, AttributeError):
                        # Provide default interfaces if both methods fail
                        print("Warning: Could not get Windows interfaces from Scapy")
                        interfaces = [
                            {'name': 'default', 'description': 'System Default Interface'},
                            {'name': 'loopback', 'description': 'Loopback Interface'}
                        ]
            else:
                # On Linux/macOS, get interfaces from Scapy
                try:
                    interfaces = scapy.get_if_list()
                    interfaces = [{'name': iface, 'description': iface} for iface in interfaces]
                except AttributeError:
                    print("Warning: Could not get interfaces from Scapy")
                    interfaces = [{'name': 'lo', 'description': 'Loopback Interface'}]
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        # Provide default interfaces as fallback
        interfaces = [
            {'name': 'default', 'description': 'System Default Interface'},
            {'name': 'loopback', 'description': 'Loopback Interface'}
        ]
    
    # Always ensure we have at least one interface
    if not interfaces:
        interfaces = [{'name': 'default', 'description': 'System Default Interface'}]
        
    return interfaces

def generate_plots(predictions, confidence):
    """Generate plots for visualization and return as base64 encoded images"""
    # Create a DataFrame with predictions
    results = pd.DataFrame({
        'Predicted': predictions,
        'Confidence': confidence
    })
    
    # Plot 1: Distribution of Predictions
    plt.figure(figsize=(10, 6))
    ax = sns.countplot(x='Predicted', data=results)
    plt.title('Distribution of Predictions')
    plt.xlabel('Predicted Traffic Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    
    # Add count labels on bars
    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', 
                  (p.get_x() + p.get_width() / 2., p.get_height()),
                  ha = 'center', va = 'bottom',
                  xytext = (0, 5), textcoords = 'offset points')
    
    plt.tight_layout()
    
    # Save plot to memory
    img_buf1 = io.BytesIO()
    plt.savefig(img_buf1, format='png')
    img_buf1.seek(0)
    img1_base64 = base64.b64encode(img_buf1.getvalue()).decode('utf-8')
    plt.close()
    
    # Plot 2: Confidence Score Distribution
    plt.figure(figsize=(10, 6))
    sns.histplot(results['Confidence'], bins=20, kde=True)
    plt.title('Confidence Score Distribution')
    plt.xlabel('Confidence')
    plt.ylabel('Count')
    plt.axvline(0.9, color='r', linestyle='--', label='90% Confidence')
    plt.legend()
    
    # Save plot to memory
    img_buf2 = io.BytesIO()
    plt.savefig(img_buf2, format='png')
    img_buf2.seek(0)
    img2_base64 = base64.b64encode(img_buf2.getvalue()).decode('utf-8')
    plt.close()
    
    return img1_base64, img2_base64

def start_live_capture(iface, batch_size=50):
    """Start live packet capture in a separate thread"""
    global live_capture_active, live_packet_data_batch, live_results
    
    # Reset live data
    live_packet_data_batch = []
    live_results = []
    live_capture_active = True
    
    # Configure Scapy for Windows L3 sniffing if needed
    if platform.system() == "Windows":
        try:
            conf.L3socket = L3RawSocket
            print("Configured Scapy to use L3RawSocket for sniffing on Windows.")
        except Exception as e:
            print(f"Warning: Could not set Scapy L3RawSocket on Windows: {e}")
    
    def capture_and_process():
        global live_capture_active, live_packet_data_batch, live_results
        
        packet_count_total = 0
        while live_capture_active:
            # Reset batch for new sniffing
            live_packet_data_batch = []
            
            # Sniff packets
            try:
                capture_kwargs = {"prn": packet_handler, "store": 0}
                if iface and iface != 'default':
                    capture_kwargs["iface"] = iface
                
                # Sniff a batch of packets with a short timeout
                sniff(count=batch_size, timeout=5, **{k:v for k,v in capture_kwargs.items() if k not in ['timeout', 'count']})
                
                packet_count_total += len(live_packet_data_batch)
                print(f"\n--- Captured batch of {len(live_packet_data_batch)} packets (Total: {packet_count_total}) ---")
                
                if not live_packet_data_batch:
                    continue
                
                # Extract features
                live_df = extract_features_from_live_packets(live_packet_data_batch, LOADED_FEATURE_COLUMNS_GLOBAL)
                
                if live_df is None or live_df.empty:
                    continue
                
                # Preprocess and predict
                X, _ = preprocess_data(live_df, LOADED_FEATURE_COLUMNS_GLOBAL, 
                                       model_expected_num_features, scaler, is_live_data=True)
                
                if X is not None and X.shape[0] > 0:
                    predictions, confidence, _ = predict_malicious_traffic(model, X, classes)
                    
                    # Store results for the web interface
                    for i in range(len(predictions)):
                        result = {
                            'id': len(live_results) + 1,
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'prediction': predictions[i],
                            'confidence': float(confidence[i]),
                            'is_malicious': predictions[i] != 'Normal Traffic'
                        }
                        live_results.append(result)
                        
                        # If more than 1000 results, keep only the most recent 1000
                        if len(live_results) > 1000:
                            live_results = live_results[-1000:]
            
            except Exception as e:
                print(f"Error in live capture: {e}")
                time.sleep(2)  # Wait before retrying
    
    # Start capture thread
    thread = Thread(target=capture_and_process)
    thread.daemon = True
    thread.start()
    
    return thread

def stop_live_capture():
    """Stop the live packet capture"""
    global live_capture_active
    live_capture_active = False

# Flask routes - Modified to return JSON responses
@app.route('/')
def home():
    interfaces = get_network_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400
    
    if file and file.filename.endswith('.csv'):
        # Save the file temporarily
        file_path = os.path.join('uploads', 'temp.csv')
        os.makedirs('uploads', exist_ok=True)
        file.save(file_path)
        
        # Process the file
        X, orig_data_features = preprocess_data(file_path, loaded_feature_columns, 
                                              model_expected_num_features, scaler)
        
        if X is None:
            return jsonify({'status': 'error', 'message': 'Error processing file. Please check format.'}), 400
        
        # Make predictions
        predictions, confidence, _ = predict_malicious_traffic(model, X, classes)
        
        # Generate visualizations
        plot1_base64, plot2_base64 = generate_plots(predictions, confidence)
        
        # Calculate summary statistics
        malicious_count = sum(1 for p in predictions if p != 'Normal Traffic')
        total_count = len(predictions)
        malicious_percent = (malicious_count / total_count) * 100 if total_count > 0 else 0
        
        # Create breakdown by type
        breakdown = []
        for cls in classes:
            cls_count = sum(1 for p in predictions if p == cls)
            cls_percent = (cls_count / total_count) * 100 if total_count > 0 else 0
            breakdown.append({
                'type': cls,
                'count': cls_count,
                'percent': cls_percent
            })
        
        # Prepare result data
        results = []
        for i in range(len(predictions)):
            results.append({
                'id': i + 1,
                'prediction': predictions[i],
                'confidence': float(confidence[i]),
                'is_malicious': predictions[i] != 'Normal Traffic'
            })
        
        return jsonify({
            'status': 'success',
            'results': results,
            'total_count': total_count,
            'malicious_count': malicious_count,
            'malicious_percent': malicious_percent,
            'breakdown': breakdown,
            'plot1': plot1_base64,
            'plot2': plot2_base64
        })
    
    return jsonify({'status': 'error', 'message': 'Invalid file format'}), 400

@app.route('/start_live', methods=['POST'])
def start_live():
    global live_capture_thread
    
    if live_capture_thread and live_capture_thread.is_alive():
        return jsonify({'status': 'error', 'message': 'Live capture already running'})
    
    iface = request.form.get('interface', 'default')
    batch_size = int(request.form.get('batch_size', 50))
    
    live_capture_thread = start_live_capture(iface, batch_size)
    
    return jsonify({'status': 'success'})

@app.route('/stop_live', methods=['POST'])
def stop_live():
    stop_live_capture()
    return jsonify({'status': 'success'})

@app.route('/get_live_results')
def get_live_results():
    global live_results
    
    # Get results since the last_id
    last_id = request.args.get('last_id', '0')
    last_id = int(last_id) if last_id.isdigit() else 0
    
    # Return new results
    new_results = [r for r in live_results if r['id'] > last_id]
    
    # Calculate summary statistics
    malicious_count = sum(1 for r in live_results if r['is_malicious'])
    total_count = len(live_results)
    
    return jsonify({
        'results': new_results,
        'total_count': total_count,
        'malicious_count': malicious_count,
        'capture_active': live_capture_active
    })

@app.route('/download_live_results', methods=['GET'])
def download_live_results():
    global live_results
    
    if not live_results:
        return jsonify({'status': 'error', 'message': 'No results available'}), 404
    
    # Create a DataFrame
    df = pd.DataFrame(live_results)
    
    # Save to a BytesIO object
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    # Return as downloadable CSV
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='live_capture_results.csv'
    )

@app.route('/settings', methods=['GET', 'POST'])
def model_settings():
    """
    Allow configuration of prediction thresholds for different attack types
    """
    global CONFIDENCE_THRESHOLDS
    
    if request.method == 'POST':
        # Update thresholds based on form data
        for attack_type in CONFIDENCE_THRESHOLDS.keys():
            threshold_key = f"threshold_{attack_type.replace(' ', '_')}"
            if threshold_key in request.form:
                try:
                    CONFIDENCE_THRESHOLDS[attack_type] = float(request.form.get(threshold_key))
                except ValueError:
                    pass  # Ignore invalid values
        
        # Save to a settings file
        with open('detection_thresholds.json', 'w') as f:
            json.dump(CONFIDENCE_THRESHOLDS, f)
            
        return jsonify({'status': 'success', 'message': 'Settings updated'})
    
    # GET request - return current settings
    return jsonify({'thresholds': CONFIDENCE_THRESHOLDS})

def initialize_app():
    """Initialize the Flask app by loading model and metadata"""
    global model, classes, loaded_feature_columns, model_expected_num_features, scaler, CONFIDENCE_THRESHOLDS
    model, classes, loaded_feature_columns, model_expected_num_features, scaler = load_model_and_metadata()
    
    # Load custom thresholds if available
    if os.path.exists('detection_thresholds.json'):
        try:
            with open('detection_thresholds.json', 'r') as f:
                custom_thresholds = json.load(f)
                CONFIDENCE_THRESHOLDS.update(custom_thresholds)
                print("Loaded custom detection thresholds")
        except Exception as e:
            print(f"Error loading custom thresholds: {e}")
    
    if model is None or classes is None or loaded_feature_columns is None or scaler is None:
        print("Failed to load model or necessary metadata. Application may not function properly.")
    else:
        print(f"Model and metadata loaded successfully. Ready for traffic analysis.")

# Initialize app on startup
initialize_app()

if __name__ == "__main__":
    # When run directly, start Flask development server
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    # When imported as a module (e.g., by a WSGI server), ensure model is loaded
    initialize_app()
