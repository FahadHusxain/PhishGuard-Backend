import joblib
import numpy as np
import os
import re

# Model Load karne ki koshish (Agar ho jaye to badhiya)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'ml_model', 'phishing_model.pkl')

model = None
try:
    model = joblib.load(MODEL_PATH)
except:
    model = None

def predict_url_security(url):
    """
    Hybrid Logic: Rules + ML
    """
    url_lower = url.lower()
    score = 0
    reasons = []

    # --- 1. HARD RULES (Ye Phishing ko pakadte hain) ---
    
    # Rule A: HTTP (Not Secure) + Sensitive Keyword
    suspicious_keywords = ['login', 'signin', 'bank', 'account', 'update', 'verify', 'secure', 'wallet', 'password']
    has_keyword = any(word in url_lower for word in suspicious_keywords)
    
    if 'https' not in url_lower and has_keyword:
        score += 60
        reasons.append("Insecure Login Page (HTTP)")

    # Rule B: IP Address in URL
    ip_pattern = r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url_lower):
        score += 50
        reasons.append("IP Address detected")

    # Rule C: Suspicious Length/Chars
    if len(url) > 75:
        score += 20
    if url.count('@') > 0:
        score += 30
        reasons.append("Contains '@' symbol")

    # --- 2. ML MODEL DECISION ---
    ml_verdict = "SAFE"
    if model:
        try:
            # Simple Feature Extraction for Model
            features = [
                len(url), url.count('.'), url.count('-'), url.count('@'),
                url.count('?'), url.count('='), url.count('https'),
                url.count('www'), sum(c.isdigit() for c in url)/len(url),
                sum(not c.isalnum() for c in url)/len(url)
            ]
            # Prediction
            prob = model.predict_proba([features])[0][1] * 100
            if prob > 50:
                score += prob / 2  # Model ka score add karo
                ml_verdict = "PHISHING"
        except:
            pass

    # --- 3. FINAL DECISION ---
    # Agar Score 50 se upar hai, to THREAT hai
    if score >= 50:
        return {
            'status': 'PHISHING',
            'confidence': min(score + 10, 99),
            'message': reasons[0] if reasons else 'Suspicious Pattern Detected'
        }
    else:
        return {
            'status': 'SAFE',
            'confidence': 95,
            'message': 'Verified Safe'
        }