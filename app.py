from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import os
import tldextract
import requests
import re
import socket
import logging
from datetime import datetime
import Levenshtein
from urllib.parse import urlparse
from feature_extractor import extract_features

app = Flask(__name__)

# Ensure logs dir
os.makedirs('logs', exist_ok=True)
logging.basicConfig(filename='logs/scan_history.log', level=logging.INFO, 
                    format='%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

KNOWN_BRANDS = {
    'google': 'https://google.com', 'paypal': 'https://paypal.com', 'apple': 'https://apple.com',
    'microsoft': 'https://microsoft.com', 'amazon': 'https://amazon.com', 'netflix': 'https://netflix.com',
    'chase': 'https://chase.com', 'bankofamerica': 'https://bankofamerica.com', 'wellsfargo': 'https://wellsfargo.com',
    'facebook': 'https://facebook.com', 'instagram': 'https://instagram.com', 'twitter': 'https://twitter.com',
    'linkedin': 'https://linkedin.com', 'github': 'https://github.com', 'coinbase': 'https://coinbase.com',
    'chowdeck': 'https://chowdeck.com', 'paystack': 'https://paystack.com', 'jumia': 'https://jumia.com',
    'kuda': 'https://kuda.com', 'flutterwave': 'https://flutterwave.com', 'opay': 'https://opayweb.com',
    'moniepoint': 'https://moniepoint.com', 'chippercash': 'https://chippercash.com', 'konga': 'https://konga.com',
    'shopee': 'https://shopee.com', 'flipkart': 'https://flipkart.com', 'lazada': 'https://lazada.com',
    'grab': 'https://grab.com', 'gojek': 'https://gojek.com', 'zomato': 'https://zomato.com',
    'swiggy': 'https://swiggy.com', 'paytm': 'https://paytm.com', 'mercadolibre': 'https://mercadolibre.com',
    'nubank': 'https://nubank.com.br', 'rappi': 'https://rappi.com', 'ifood': 'https://ifood.com.br',
    'pagseguro': 'https://pagseguro.uol.com.br', 'revolut': 'https://revolut.com', 'monzo': 'https://monzo.com',
    'n26': 'https://n26.com', 'klarna': 'https://klarna.com', 'deliveroo': 'https://deliveroo.co.uk',
    'zalando': 'https://zalando.com'
}

MODEL_PATH = 'phishing_model.joblib'
try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    model = None

def is_internal_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
    except socket.error:
        return False

def generate_threat_summary(f_dict):
    summary = []
    if f_dict['Length'] > 75: summary.append("URL is significantly longer than average domains.")
    if f_dict['Dots'] >= 3: summary.append("Multiple subdomains detected, a common evasion tactic.")
    if f_dict['Hyphens'] == 1: summary.append("URL contains dashes, often used in typosquatting.")
    if f_dict['HTTPS'] == 0: summary.append("Connection is not secured by HTTPS.")
    if f_dict['Suspicious Term'] == 1: summary.append("Domain contains words commonly used in social engineering (e.g., 'login', 'free').")
    if f_dict['High-Risk TLD'] == 1: summary.append("Domain ends in a high-risk Zone (.xyz, .top, etc.).")
    if f_dict['At Symbol'] == 1: summary.append("URL contains an '@' symbol, masking the true destination.")
    if f_dict['Entropy'] > 3.5: summary.append("Domain name appears mathematically random or auto-generated.")
    if f_dict['Domain Age'] > -1 and f_dict['Domain Age'] < 30:
        summary.append(f"Domain is highly suspicious: newly registered ({f_dict['Domain Age']} days ago).")
    return summary

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Yikes! We are missing the AI model.'}), 500
    
    data = request.json
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'Oops! URL came back empty.'}), 400

    # Basic schema validation
    if re.match(r'^(javascript|data):', raw_url, re.IGNORECASE):
        return jsonify({'error': 'Invalid or malicious schema detected.'}), 400

    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url

    parsed_url = urlparse(raw_url)
    if is_internal_ip(parsed_url.netloc):
        return jsonify({'error': 'Nice try! Internal IP scans (SSRF) are blocked.'}), 403

    features = extract_features(raw_url)
    f_dict = {
        'Length': features[0], 'Dots': features[1], 'Hyphens': features[2], 'HTTPS': features[3],
        'Suspicious Term': features[4], 'Brand Typo': features[5], 'Known Brand': features[6],
        'High-Risk TLD': features[7], 'Is HTTP': features[8], 'Entropy': features[9],
        'At Symbol': features[10], 'Domain Age': features[11]
    }

    # Whitelisting
    is_whitelisted = False
    if 'onrender.com' in parsed_url.netloc:
        f_dict['Suspicious Term'] = 0
        features[4] = 0
        is_whitelisted = True

    is_live = False
    ping_warning = ""
    is_parked = False
    redirects_to_social = False

    try:
        r = requests.get(raw_url, timeout=3, allow_redirects=True, stream=True)
        is_live = True
        
        # Parked Check
        content_sample = next(r.iter_content(2048)).decode('utf-8', errors='ignore').lower()
        if 'for sale' in content_sample or 'hugedomains' in content_sample:
            is_parked = True
        
        if len(content_sample) < 1024 and '<html' not in content_sample:
            is_parked = True
            
        final_url = r.url
        if any(social in final_url for social in ['t.me/', 'twitter.com/', 'x.com/']):
            redirects_to_social = True
            
    except requests.exceptions.SSLError:
        ping_warning = "Warning: URL has severe SSL/Certificate errors."
    except requests.exceptions.RequestException:
        ping_warning = "Warning: This URL does not appear to exist or is currently offline."

    # Intent vs Identity Logic (Levenstein)
    status = "Safe"
    ext = tldextract.extract(raw_url)
    clean_domain = ext.domain.lower().replace('-', '')
    
    suggested_site = None
    lev_caution = False
    lev_phish = False

    if len(clean_domain) >= 5 and not is_whitelisted:
        for brand, real_url in KNOWN_BRANDS.items():
            sim = Levenshtein.ratio(clean_domain, brand)
            if sim >= 0.80 and clean_domain != brand:
                if features[11] > -1 and features[11] < 30:
                    lev_phish = True
                else: # Age > 30 or unknown but valid SSL check
                    if is_live and 'SSL' not in ping_warning:
                        lev_caution = True
                
                suggested_site = {'name': brand.capitalize(), 'url': real_url}
                break

    features_array = np.array(features).reshape(1, -1)
    prediction_num = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]

    # Overrides
    if lev_phish or is_parked or redirects_to_social or features[5] == 1 or features[7] == 1:
        prediction_num = 1
        probabilities[1] = 0.99
    elif lev_caution:
        status = "Caution"
    
    if prediction_num == 1:
        status = "Phishing"

    confidence = round(probabilities[prediction_num] * 100, 2)
    threat_summary = generate_threat_summary(f_dict)
    
    if is_parked: threat_summary.append("Domain appears to be Empty or 'Parked for Sale'.")
    if redirects_to_social: threat_summary.append("URL suspiciously redirects directly to a social media platform.")
    if lev_phish: threat_summary.append(f"Highly similar to {suggested_site['name']} but newly registered. Confirmed Phishing.")

    if len(threat_summary) == 0 and status == "Safe":
        threat_summary.append("No active heuristic threats detected.")

    logging.info(f"URL: {raw_url} | Prob: {confidence}% | Status: {status}")

    bio = ""
    safe_link = ""
    if status == "Safe" and is_live:
        domain_name = re.sub(r'[^a-zA-Z0-9\s]', '', ext.domain.capitalize())
        bio = f"It looks like you are trying to visit {domain_name}. Our AI has recognized this as a legitimate and secure destination."
        safe_link = raw_url

    return jsonify({
        'prediction': status,
        'confidence': confidence,
        'bio': bio,
        'safe_link': safe_link,
        'is_live': is_live,
        'ping_warning': ping_warning,
        'suggested_site': suggested_site,
        'threat_summary': threat_summary
    })

if __name__ == '__main__':
    app.run(debug=True)
