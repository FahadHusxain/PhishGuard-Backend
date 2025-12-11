import joblib
import numpy as np
import os
import re

# Model Load Karna (Professional Way)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'ml_model', 'phishing_model.pkl')

model = None
try:
    model = joblib.load(MODEL_PATH)
    print("✅ ML Model Loaded Successfully (Optimized Mode)")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    # Agar model na mile to bhi code crash na kare
    model = None

def extract_features(url):
    """
    Feature Extraction without Pandas (Pure optimized Python)
    Same logic as training, but lighter on RAM.
    """
    features = []
    
    # 1. Length Features
    features.append(len(url))
    features.append(len(new_url.hostname) if 'new_url' in locals() else len(url.split('/')[0])) # Hostname len
    
    # 2. Count Features
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('%'))
    features.append(url.count('https'))
    features.append(url.count('http') - url.count('https')) # HTTP count
    features.append(url.count('www'))
    
    # 3. Digit Ratio
    digits = sum(c.isdigit() for c in url)
    features.append(digits / len(url) if len(url) > 0 else 0)
    
    # 4. Special Char Ratio
    special_chars = sum(not c.isalnum() for c in url)
    features.append(special_chars / len(url) if len(url) > 0 else 0)

    return np.array([features]) # Return as Numpy Array (Not DataFrame)

def predict_url_security(url):
    """
    Predict using the loaded ML Model
    """
    if model is None:
        # Fallback agar model load na ho (Crash prevention)
        return {'status': 'UNKNOWN', 'confidence': 0, 'message': 'Model not loaded'}

    try:
        # 1. Extract Features
        features_array = extract_features(url)
        
        # 2. Predict (Using Scikit-Learn)
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0][1] * 100
        
        # 3. Result Format
        if prediction == 1 or probability > 50:
            return {
                'status': 'PHISHING',
                'confidence': round(probability, 2),
                'message': 'ML Model Detected Threat'
            }
        else:
            return {
                'status': 'SAFE',
                'confidence': round(100 - probability, 2),
                'message': 'ML Model Verified Safe'
            }
            
    except Exception as e:
        print(f"Prediction Error: {e}")
        # Agar ML fail ho (feature mismatch), to safe side par raho
        return {'status': 'SAFE', 'confidence': 0, 'message': 'Scan Error'}