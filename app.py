from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import os
import tldextract
import requests
import difflib
from feature_extractor import extract_features

app = Flask(__name__)

KNOWN_BRANDS = {
    # Global Tech & Finance
    'google': 'https://google.com',
    'paypal': 'https://paypal.com',
    'apple': 'https://apple.com',
    'microsoft': 'https://microsoft.com',
    'amazon': 'https://amazon.com',
    'netflix': 'https://netflix.com',
    'chase': 'https://chase.com',
    'bankofamerica': 'https://bankofamerica.com',
    'wellsfargo': 'https://wellsfargo.com',
    'facebook': 'https://facebook.com',
    'instagram': 'https://instagram.com',
    'twitter': 'https://twitter.com',
    'linkedin': 'https://linkedin.com',
    'github': 'https://github.com',
    'coinbase': 'https://coinbase.com',
    
    # Africa
    'chowdeck': 'https://chowdeck.com',
    'paystack': 'https://paystack.com',
    'jumia': 'https://jumia.com',
    'kuda': 'https://kuda.com',
    'flutterwave': 'https://flutterwave.com',
    'opay': 'https://opayweb.com',
    'moniepoint': 'https://moniepoint.com',
    'chippercash': 'https://chippercash.com',
    'konga': 'https://konga.com',

    # Asia & India
    'shopee': 'https://shopee.com',
    'flipkart': 'https://flipkart.com',
    'lazada': 'https://lazada.com',
    'grab': 'https://grab.com',
    'gojek': 'https://gojek.com',
    'zomato': 'https://zomato.com',
    'swiggy': 'https://swiggy.com',
    'paytm': 'https://paytm.com',

    # Latin America
    'mercadolibre': 'https://mercadolibre.com',
    'nubank': 'https://nubank.com.br',
    'rappi': 'https://rappi.com',
    'ifood': 'https://ifood.com.br',
    'pagseguro': 'https://pagseguro.uol.com.br',

    # Europe & UK
    'revolut': 'https://revolut.com',
    'monzo': 'https://monzo.com',
    'n26': 'https://n26.com',
    'klarna': 'https://klarna.com',
    'deliveroo': 'https://deliveroo.co.uk',
    'zalando': 'https://zalando.com'
}

# Load the model if it exists
# (Flask will automatically reload this file when we make this comment edit)
MODEL_PATH = 'phishing_model.joblib'
try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    model = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Defensive check: Do we have a loaded brain?
    if not model:
        return jsonify({'error': 'Yikes! We are missing the AI model. Did you run train_model.py?'}), 500

    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url:
        return jsonify({'error': 'Oops! URL came back empty. Provide a real link.'}), 400

    # Auto-format http just to be absolutely bulletproof on the backend
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url

    # Ping the target to check if it's alive (Compromise: flag it, but don't stop the AI)
    is_live = True
    ping_warning = ""
    
    try:
        requests.head(raw_url, timeout=3, allow_redirects=True)
    except requests.exceptions.SSLError:
        is_live = False
        ping_warning = "Warning: URL has severe SSL/Certificate errors."
    except requests.exceptions.RequestException:
        is_live = False
        ping_warning = "Warning: This URL does not appear to exist or is currently offline."

    # Look for typo-brands if the site is offline
    suggested_site = None
    if not is_live:
        ext = tldextract.extract(raw_url)
        # remove hyphens and dots to match known brands easily
        clean_domain = ext.domain.lower().replace('-', '')
        # Drop cutoff to 0.72 so that inputs like 'jumaii' flag correctly
        matches = difflib.get_close_matches(clean_domain, KNOWN_BRANDS.keys(), n=1, cutoff=0.72)
        if matches:
            matched_key = matches[0]
            display_name = matched_key.capitalize()
            if matched_key == 'bankofamerica': display_name = "Bank of America"
            if matched_key == 'wellsfargo': display_name = "Wells Fargo"
            suggested_site = {
                'name': display_name,
                'url': KNOWN_BRANDS[matched_key]
            }

    # Ask our extractor to crunch the URL into specific digital flags
    features = extract_features(raw_url)
    
    # Scikit-learn random forests get cranky if it's not a 2D array, so we reshape it -> (1 row, -1 columns)
    features_array = np.array(features).reshape(1, -1)
    
    # Let the forest vote and predict the outcome
    prediction_num = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]

    # HARDCODED OVERRIDES for strict security
    # 1. If it's a known typo (has_typo or we suggested a brand), it is a phishing attempt.
    if suggested_site or features[5] == 1:
        prediction_num = 1
        probabilities[1] = 0.99
    # 2. If it contains a highly malicious TLD (.xyz, .top), do not trust the AI. Mark as phishing.
    elif features[7] == 1:
        prediction_num = 1
        probabilities[1] = 0.95
    
    prediction = "Phishing" if prediction_num == 1 else "Safe"
    confidence = round(probabilities[prediction_num] * 100, 2)
    
    # Generate a polite Bio dynamically if the site is Safe
    bio = ""
    safe_link = ""
    # Only offer a bio and a clickable button to the site if the AI thinks it's safe AND the site actually works
    if prediction == "Safe" and is_live:
        ext = tldextract.extract(raw_url)
        domain_name = ext.domain.capitalize()
        # Fallback if domain parses weirdly (like brackets from injection attempts)
        import re
        domain_name = re.sub(r'[^a-zA-Z0-9\s]', '', domain_name)
        if not domain_name:
            domain_name = "This website"
            
        bio = f"It looks like you are trying to visit {domain_name}. Our AI has recognized this as a legitimate and secure destination."
        safe_link = raw_url
    
    return jsonify({
        'prediction': prediction,
        'confidence': confidence,
        'bio': bio,
        'safe_link': safe_link,
        'is_live': is_live,
        'ping_warning': ping_warning,
        'suggested_site': suggested_site,
        'features': {
            'Length': features[0],
            'Dots': features[1],
            'Hyphens': features[2],
            'HTTPS': features[3],
            'Suspicious Term': features[4],
            'Brand Typo': features[5],
            'Known Brand': features[6],
            'High-Risk TLD': features[7],
            'Is HTTP': features[8]
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
