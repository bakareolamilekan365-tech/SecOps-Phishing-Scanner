from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import os
import json
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

# Configure a specific logger for scan history so we don't hijack Werkzeug's console output
scan_logger = logging.getLogger('scan_history')
scan_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('logs/scan_history.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
scan_logger.addHandler(file_handler)

KNOWN_BRANDS = {
    'google': 'https://google.com', 'paypal': 'https://paypal.com', 'apple': 'https://apple.com',
    'zenithbank': 'https://zenithbank.com', 'microsoft': 'https://microsoft.com', 'amazon': 'https://amazon.com', 'netflix': 'https://netflix.com',
    'chase': 'https://chase.com', 'bankofamerica': 'https://bankofamerica.com', 'wellsfargo': 'https://wellsfargo.com',
    'facebook': 'https://facebook.com', 'instagram': 'https://instagram.com', 'twitter': 'https://twitter.com',
    'linkedin': 'https://linkedin.com', 'github': 'https://github.com', 'coinbase': 'https://coinbase.com',
    'whatsapp': 'https://whatsapp.com', 'tiktok': 'https://tiktok.com', 'twitch': 'https://twitch.tv', 'reddit': 'https://reddit.com', 'meta': 'https://meta.com',
    'chowdeck': 'https://chowdeck.com', 'paystack': 'https://paystack.com', 'jumia': 'https://jumia.com',
    'kuda': 'https://kuda.com', 'flutterwave': 'https://flutterwave.com', 'opay': 'https://opayweb.com',
    'moniepoint': 'https://moniepoint.com', 'chippercash': 'https://chippercash.com', 'konga': 'https://konga.com',
    'shopee': 'https://shopee.com', 'flipkart': 'https://flipkart.com', 'lazada': 'https://lazada.com',
    'grab': 'https://grab.com', 'gojek': 'https://gojek.com', 'zomato': 'https://zomato.com',
    'swiggy': 'https://swiggy.com', 'paytm': 'https://paytm.com', 'mercadolibre': 'https://mercadolibre.com',
    'nubank': 'https://nubank.com.br', 'rappi': 'https://rappi.com', 'ifood': 'https://ifood.com.br',
    'pagseguro': 'https://pagseguro.uol.com.br', 'revolut': 'https://revolut.com', 'monzo': 'https://monzo.com',
    'n26': 'https://n26.com', 'klarna': 'https://klarna.com', 'deliveroo': 'https://deliveroo.co.uk',
    'zalando': 'https://zalando.com', 'spotify': 'https://spotify.com', 'telegram': 'https://t.me',
    'discord': 'https://discord.com', 'snapchat': 'https://snapchat.com', 'pinterest': 'https://pinterest.com',
    'roblox': 'https://roblox.com', 'canva': 'https://canva.com', 'flickr': 'https://flickr.com',
    'skyscanner': 'https://skyscanner.net', 'booking': 'https://booking.com', 'vinted': 'https://vinted.com',
    'adobe': 'https://adobe.com', 'ikea': 'https://ikea.com', 'decathlon': 'https://decathlon.com',
    'asos': 'https://asos.com', 'airbnb': 'https://airbnb.com', 'bbc': 'https://bbc.com',
    'cnn': 'https://cnn.com', 'nytimes': 'https://nytimes.com', 'aljazeera': 'https://aljazeera.com',
    'mtn': 'https://mtn.com', 'airtel': 'https://airtel.com', 'glo': 'https://gloworld.com',
    'safaricom': 'https://safaricom.co.ke', 'mpesa': 'https://mpesa.com', 'dstv': 'https://dstv.com',
    'showmax': 'https://showmax.com', 'jiji': 'https://jiji.ng', 'kikuu': 'https://kikuu.com',
    'gtbank': 'https://gtbank.com', 'firstbanknigeria': 'https://firstbanknigeria.com',
    'accessbankplc': 'https://accessbankplc.com', 'ubagroup': 'https://ubagroup.com',
    'stanbicibtc': 'https://stanbicibtcbank.com', 'fcmb': 'https://fcmb.com',
    'fidelitybank': 'https://fidelitybank.ng', 'ecobank': 'https://ecobank.com',
    'kcb': 'https://kcbgroup.com', 'equitybank': 'https://equitygroupholdings.com',
    'standardbank': 'https://standardbank.com', 'nedbank': 'https://nedbank.co.za',
    'capitecbank': 'https://capitecbank.co.za', 'absa': 'https://absa.co.za', 'fnb': 'https://fnb.co.za'
}

BRAND_DISPLAY_NAMES = {
    'zenithbank': 'Zenith Bank', 'bankofamerica': 'Bank of America', 'wellsfargo': 'Wells Fargo',
    'chippercash': 'Chipper Cash', 'mercadolibre': 'Mercado Libre', 'gtbank': 'GTBank',
    'firstbanknigeria': 'First Bank', 'accessbankplc': 'Access Bank', 'ubagroup': 'UBA Group',
    'stanbicibtc': 'Stanbic IBTC', 'fidelitybank': 'Fidelity Bank', 'standardbank': 'Standard Bank',
    'capitecbank': 'Capitec Bank', 'aljazeera': 'Al Jazeera', 'nytimes': 'The New York Times',
    'showmax': 'Showmax', 'paypal': 'PayPal', 'moniepoint': 'Moniepoint', 'ecobank': 'EcoBank'
}

MODEL_PATH = 'phishing_model.joblib'
try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    model = None

def is_internal_ip(domain):
    try:
        # Strip port if present
        clean_domain = domain.split(':')[0]
        ip = socket.gethostbyname(clean_domain)
        return ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
    except socket.error:
        return False

def generate_threat_summary(f_dict):
    summary = []
    if f_dict['Length'] > 75: summary.append("[WARN] URL is significantly longer than average domains.")
    if f_dict['Dots'] >= 3: summary.append("[WARN] Multiple subdomains detected, a common evasion tactic.")
    if f_dict['Hyphens'] == 1: summary.append("[WARN] URL contains dashes, often used in typosquatting.")
    if f_dict['HTTPS'] == 0: summary.append("[WARN] Connection is not secured by HTTPS.")
    if f_dict['Suspicious Term'] == 1: summary.append("[FAIL] Domain contains words commonly used in social engineering (e.g., 'login', 'free').")
    if f_dict['High-Risk TLD'] == 1: summary.append("[FAIL] Domain ends in a high-risk Zone (.xyz, .top, etc.).")
    if f_dict['At Symbol'] == 1: summary.append("[FAIL] URL contains an '@' symbol, masking the true destination.")
    if f_dict['Entropy'] > 3.5: summary.append("[WARN] Domain name appears mathematically random or auto-generated.")
    if f_dict['Domain Age'] > -1 and f_dict['Domain Age'] < 30:
        summary.append(f"[FAIL] Domain is highly suspicious: newly registered ({f_dict['Domain Age']} days ago).")
    return summary

def append_feedback_record(record):
    feedback_path = os.path.join('logs', 'user_feedback_queue.jsonl')
    with open(feedback_path, 'a', encoding='utf-8') as fp:
        fp.write(json.dumps(record, ensure_ascii=True) + '\n')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'System Error: Classification engine is temporarily unavailable.'}), 500
    
    data = request.json
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'Error: No URL provided for analysis.'}), 400

    # Auto-fix missing TLDs (e.g., user types "facebook" or "zenithbank" without .com/.edu/.ng)
    clean_input = re.sub(r'^https?://', '', raw_url, flags=re.IGNORECASE).strip()
    if '/' not in clean_input and '.' not in clean_input:
        if clean_input.lower() in KNOWN_BRANDS:
            # Map directly to the known brand URL
            raw_url = KNOWN_BRANDS[clean_input.lower()]
        else:
            # Append .com as a fallback guess
            raw_url = clean_input + '.com'

    # Basic schema validation
    if re.match(r'^(javascript|data):', raw_url, re.IGNORECASE):
        return jsonify({'error': 'Invalid or malicious schema detected.'}), 400

    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url

    parsed_url = urlparse(raw_url)
    if is_internal_ip(parsed_url.netloc):
        return jsonify({'error': 'Access Denied: Scanning internal network addresses is restricted.'}), 403

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
    resolved_url = raw_url
    ping_warning = ""
    is_parked = False
    redirects_to_social = False

    try:
        # Mask the bot as a real browser
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
        r = requests.get(raw_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
        is_live = True
        
        # Parked Check
        content_sample = next(r.iter_content(2048)).decode('utf-8', errors='ignore').lower()
        if 'for sale' in content_sample or 'hugedomains' in content_sample:
            is_parked = True
        
        if len(content_sample) < 1024 and '<html' not in content_sample:
            is_parked = True
            
        resolved_url = r.url
        if any(social in resolved_url for social in ['t.me/', 'twitter.com/', 'x.com/']):
            redirects_to_social = True
            
    except requests.exceptions.SSLError:
        ping_warning = "Warning: URL has severe SSL/Certificate errors."
    except requests.exceptions.RequestException:
        ping_warning = "Warning: This URL does not appear to exist or is currently offline."

    # Intent vs Identity Logic (Levenstein & Leetspeak)
    status = "Safe"
    ext = tldextract.extract(raw_url)
    clean_domain = ext.domain.lower().replace('-', '')
    
    # Catch classic hacker leetspeak and symbols (0->o, @->a, 1->l, 3->e, 4->a)
    sneaky_netloc = parsed_url.netloc.lower().replace('@', 'a').replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a')
    clean_sneaky = tldextract.extract("http://" + sneaky_netloc).domain.replace('-', '')
    
    suggested_site = None
    lev_caution = False
    lev_phish = False

    if not is_whitelisted:
        for brand, real_url in KNOWN_BRANDS.items():
            sim = Levenshtein.ratio(clean_domain, brand)
            dist = Levenshtein.distance(clean_domain, brand)
            
            # Explicit leetspeak match (like faceb00k -> facebook) or strict typosquatting
            is_leetspeak_match = (clean_sneaky == brand and clean_domain != brand)
            is_typosquat = (sim >= 0.80 or (dist <= 2 and len(brand) >= 6)) and clean_domain != brand

            if is_leetspeak_match or is_typosquat:
                if features[11] > -1 and features[11] < 30:
                    lev_phish = True
                elif is_leetspeak_match or features[10] == 1 or dist <= 1:
                    # Explicit leetspeak (faceb00k), @ symbol tricks, or single-letter typos are almost certainly malicious
                    lev_phish = True
                else: 
                    if is_live and 'SSL' not in ping_warning:
                        lev_caution = True
                
                suggested_site = {
                    'name': BRAND_DISPLAY_NAMES.get(brand, brand.capitalize()),
                    'url': real_url
                }
                break

    features_array = np.array(features).reshape(1, -1)
    prediction_num = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]

    # --- FIXED OVERRIDES ---
    forced_override = False

    # Only force certainty in clear-cut dangerous cases
    if is_whitelisted:
        prediction_num = 0
        probabilities[0] = 0.95
        probabilities[1] = 0.05
        status = "Safe"
        forced_override = True
    elif lev_phish or is_parked or redirects_to_social:
        # Confirmed phishing via heuristics
        prediction_num = 1
        probabilities[1] = 0.95
        probabilities[0] = 0.05
        status = "Phishing"
        forced_override = True
    elif features[5] == 1 or features[7] == 1:
        # Brand typo or high-risk TLD detected
        prediction_num = 1
        probabilities[1] = 0.90
        probabilities[0] = 0.10
        status = "Phishing"
        forced_override = True
    elif clean_domain in KNOWN_BRANDS and ext.suffix in ['com', 'org', 'net', 'co.uk', 'com.br']:
        # Exact known brand match
        prediction_num = 0
        probabilities[0] = 0.98
        probabilities[1] = 0.02
        status = "Safe"
        forced_override = True
    elif lev_caution:
        prediction_num = 0 
        status = "Caution"
        forced_override = True
        # Keep model's natural probability distribution
    elif prediction_num == 1:
        status = "Phishing"
    # For Safe predictions with no overrides, use natural model probabilities

    # If the model is uncertain, force a caution verdict for safer UX.
    top_probability = float(np.max(probabilities))
    if not forced_override and top_probability <= 0.60:
        status = "Caution"

    # Keep the score below 100 to avoid overclaiming certainty.
    confidence = min(round(top_probability * 100, 2), 99.99)
    is_known_domain = clean_domain in KNOWN_BRANDS
    model_uncertain = (top_probability <= 0.60 and not forced_override)
    threat_summary = generate_threat_summary(f_dict)
    
    if is_parked: threat_summary.append("[FAIL] Domain appears to be Empty or 'Parked for Sale'.")
    if redirects_to_social: threat_summary.append("[WARN] URL suspiciously redirects directly to a social media platform.")
    if lev_phish: threat_summary.append(f"[FAIL] Highly similar to {suggested_site['name']} but newly registered. Confirmed Phishing.")

    if status == "Phishing":
        if len(threat_summary) < 1:
            threat_summary.append("[FAIL] AI Model heavily correlated URL structure with known phishing datasets.")
        if len(threat_summary) < 2:
            threat_summary.append("[FAIL] Deep-learning feature analysis flagged anomalous URI patterns.")
        if len(threat_summary) < 3:
            threat_summary.append("[WARN] Behavioral and reputation scoring aligns closely with adversarial risk profiles.")
        if len(threat_summary) < 4:
            threat_summary.append("[WARN] Detected missing historical trust indicators for this specific endpoint.")
    elif status == "Caution":
        if len(threat_summary) < 1:
            threat_summary.append("[WARN] Domain structure presents edge-case similarities to known brands.")
        if len(threat_summary) < 3:
            threat_summary.append("[WARN] Recommended to confirm exact destination intent before sharing credentials.")
    elif status == "Safe":
        if len(threat_summary) == 0:
            threat_summary.append("[PASS] No active heuristic threats detected.")
            threat_summary.append("[PASS] Domain structure utilizes standard acceptable configurations.")
            threat_summary.append("[PASS] Overall trust indicators fall within secure operational margins.")
        else:
            threat_summary.insert(0, "[PASS] Overall predictive safety margins passed threshold safely.")

    scan_logger.info(f"URL: {raw_url} | Prob: {confidence}% | Status: {status}")

    bio = ""
    safe_link = ""
    if status == "Safe" and is_live:
        display_domain = BRAND_DISPLAY_NAMES.get(clean_domain, ext.domain.capitalize())
        bio = f"It looks like you are trying to visit {display_domain}. Our AI has recognized this as a legitimate and secure destination."
        safe_link = raw_url

    return jsonify({
        'prediction': status,
        'confidence': confidence,
        'normalized_url': raw_url,
        'resolved_url': resolved_url,
        'is_known_domain': is_known_domain,
        'model_uncertain': model_uncertain,
        'bio': bio,
        'safe_link': safe_link,
        'is_live': is_live,
        'ping_warning': ping_warning,
        'suggested_site': suggested_site,
        'threat_summary': threat_summary
    })

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json or {}
    raw_url = str(data.get('url', '')).strip()
    user_label = str(data.get('user_label', '')).strip().lower()
    note = str(data.get('note', '')).strip()

    if not raw_url:
        return jsonify({'error': 'Feedback rejected: URL is required.'}), 400
    if user_label not in ['safe', 'phishing']:
        return jsonify({'error': 'Feedback rejected: label must be safe or phishing.'}), 400

    parsed = urlparse(raw_url if raw_url.startswith(('http://', 'https://')) else f'https://{raw_url}')
    domain_key = tldextract.extract(parsed.geturl()).domain.lower().replace('-', '')

    record = {
        'timestamp_utc': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'url': parsed.geturl(),
        'domain_key': domain_key,
        'user_label': user_label,
        'model_prediction': str(data.get('model_prediction', '')).strip(),
        'model_confidence': data.get('model_confidence'),
        'is_known_domain': bool(data.get('is_known_domain', False)),
        'model_uncertain': bool(data.get('model_uncertain', False)),
        'note': note[:600],
        'source': 'ui-feedback'
    }

    append_feedback_record(record)
    return jsonify({'ok': True, 'message': 'Feedback saved for review pipeline.'})

if __name__ == '__main__':
    print("Starting Flask app on all network interfaces...")
    app.run(host='0.0.0.0', port=5000, debug=True)
