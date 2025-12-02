import os
import re  # <--- YE ZAROORI HAI (Regex ke liye)
import pickle
import numpy as np
from django.conf import settings
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from api.models import WhitelistDomain  # Database Connection

# --- 1. SETUP ---
print("🔄 Loading AI Model...")
MODEL_PATH = os.path.join(settings.BASE_DIR, 'ml_models/phishguard_cnn.h5')
TOKENIZER_PATH = os.path.join(settings.BASE_DIR, 'ml_models/tokenizer.pickle')

model = load_model(MODEL_PATH)
with open(TOKENIZER_PATH, 'rb') as handle:
    tokenizer = pickle.load(handle)

print("✅ AI Brain Ready!")

# --- 2. PREDICTION FUNCTION ---
def predict_url_security(url):
    print(f"\n🔍 Check: {url}") 
    
    # Step A: Safayi
    clean_url = url.replace("https://", "").replace("http://", "").replace("www.", "")
    domain = clean_url.split('/')[0]

    # Step B: Layer 1 - Whitelist Database Check (Professional Way)
    if WhitelistDomain.objects.filter(domain=domain).exists():
        print("🛡️ DEBUG: Whitelist DB HIT!")
        return {
            "status": "SAFE",
            "confidence": 100.00,
            "message": "Verified Safe Brand (Top 1M Database)"
        }

    # Step C: AI Prediction & Smart Rules
    try:
        sequence = tokenizer.texts_to_sequences([clean_url])
        padded_sequence = pad_sequences(sequence, maxlen=200, padding='post', truncating='post')
        prediction = model.predict(padded_sequence)
        
        final_score = float(prediction[0][0]) # Base AI Score
        reasons = []

        # --- C. BOOSTING LOGIC (CONFIDENCE BADHANE KE LIYE) ---

        # Rule 1: Keyword Boosting
        SUSPICIOUS_KEYWORDS = ["login", "signin", "secure", "account", "update", "verify", "paypal", "bank", "wallet", "crypto"]
        found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in clean_url]
        if found_keywords:
            final_score += 0.30
            reasons.append(f"Suspicious words found: {', '.join(found_keywords)}")

        # Rule 2: IP Address Check (e.g. http://123.45.67.89)
        # Agar URL mein domain ki jagah IP hai, to ye 100% khatra hai
        ip_pattern = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)
        if ip_pattern:
            final_score += 0.50 # Seedha 50% badha do
            reasons.append("URL uses an IP address instead of a domain name.")

        # Rule 3: Too Many Dots (Subdomain Abuse)
        # e.g. paypal.secure.login.com (3 se zyada dots domain mein)
        if domain.count('.') > 3:
            final_score += 0.20
            reasons.append("Suspiciously high number of subdomains.")

        # Rule 4: @ Symbol Abuse
        if "@" in url:
            final_score += 0.40
            reasons.append("URL contains '@' symbol (Credential stealing pattern).")

        # --- D. FINAL DECISION ---
        
        # Score ko 1.0 se upar mat jane do
        final_score = min(final_score, 0.9999)

        if final_score > 0.5:
            # Agar reasons khali hain to generic message dalo
            if not reasons:
                reasons.append("AI detected abnormal structural patterns.")
            
            return {
                "status": "PHISHING",
                "confidence": round(final_score * 100, 2),
                "message": " | ".join(reasons)
            }
        else:
            return {
                "status": "SAFE",
                "confidence": round((1 - final_score) * 100, 2),
                "message": "Safe site."
            }

    except Exception as e:
        return {"status": "ERROR", "message": str(e)}