## SECTION 1 — BACKEND / CODEBASE SNIPPETS

### app.py

#### 1. /predict route

- File: app.py
- Lines: 110-330
- Title: /predict route
- Purpose: Handles URL scanning request and returns verdict payload.

```python
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
```

#### 2. input normalization logic

- File: app.py
- Lines: 121-130
- Title: input normalization logic
- Purpose: Canonicalizes incomplete user URL input before scanning.

```python
# Auto-fix missing TLDs (e.g., user types "facebook" or "zenithbank" without .com/.edu/.ng)
clean_input = re.sub(r'^https?://', '', raw_url, flags=re.IGNORECASE).strip()
if '/' not in clean_input and '.' not in clean_input:
    if clean_input.lower() in KNOWN_BRANDS:
        # Map directly to the known brand URL
        raw_url = KNOWN_BRANDS[clean_input.lower()]
    else:
        # Append .com as a fallback guess
        raw_url = clean_input + '.com'
```

#### 3. schema blocking logic

- File: app.py
- Lines: 132-133
- Title: schema blocking logic
- Purpose: Rejects dangerous non-web URL schemes.

```python
# Basic schema validation
if re.match(r'^(javascript|data):', raw_url, re.IGNORECASE):
    return jsonify({'error': 'Invalid or malicious schema detected.'}), 400
```

#### 4. SSRF/private IP blocking logic

- File: app.py
- Lines: 79-86, 138-140
- Title: SSRF/private IP blocking logic
- Purpose: Prevents scans against internal/private network addresses.

```python
def is_internal_ip(domain):
    try:
        # Strip port if present
        clean_domain = domain.split(':')[0]
        ip = socket.gethostbyname(clean_domain)
        return ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
    except socket.error:
        return False

parsed_url = urlparse(raw_url)
if is_internal_ip(parsed_url.netloc):
    return jsonify({'error': 'Access Denied: Scanning internal network addresses is restricted.'}), 403
```

#### 5. liveliness / parked-domain checking logic

- File: app.py
- Lines: 160-183
- Title: liveliness / parked-domain checking logic
- Purpose: Probes target URL and flags parked or redirect-risk behavior.

```python
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
```

#### 6. brand typo or leetspeak detection call/logic

- File: app.py
- Lines: 186-223
- Title: brand typo or leetspeak detection call/logic
- Purpose: Detects typosquatting and leetspeak impersonation against known brands.

```python
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
```

#### 7. model loading and ensemble inference

- File: app.py
- Lines: 73-76, 224-226
- Title: model loading and ensemble inference
- Purpose: Loads persisted classifier and executes prediction/probability inference.

```python
MODEL_PATH = 'phishing_model.joblib'
try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    model = None

features_array = np.array(features).reshape(1, -1)
prediction_num = model.predict(features_array)[0]
probabilities = model.predict_proba(features_array)[0]
```

#### 8. deterministic override logic

- File: app.py
- Lines: 228-256
- Title: deterministic override logic
- Purpose: Overrides probabilistic output for high-confidence security edge cases.

```python
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
```

#### 9. JSON response assembly

- File: app.py
- Lines: 314-327
- Title: JSON response assembly
- Purpose: Returns structured verdict and analysis payload to frontend.

```python
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
```

#### 10. logging block writing scan history

- File: app.py
- Lines: 20-25, 305
- Title: logging block writing scan history
- Purpose: Configures scan-history logger and appends per-scan entries.

```python
# Configure a specific logger for scan history so we don't hijack Werkzeug's console output
scan_logger = logging.getLogger('scan_history')
scan_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('logs/scan_history.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
scan_logger.addHandler(file_handler)

scan_logger.info(f"URL: {raw_url} | Prob: {confidence}% | Status: {status}")
```

### feature_extractor.py

#### 1. main feature extraction function

- File: feature_extractor.py
- Lines: 37-90
- Title: main feature extraction function
- Purpose: Computes 12 engineered URL features for model input.

```python
def extract_features(url, fast_mode=False):
    url_lower = url.lower()

    url_length = len(url)
    dot_count = url.count('.')
    has_hyphen = 1 if '-' in url else 0
    has_https = 1 if url.startswith('https://') else 0

    suspicious_words = [
        'login', 'secure', 'verify', 'account', 'update', 'banking', 'auth',
        'support', 'service', 'helpdesk', 'recovery', 'billing', 'admin', 'security',
        'confirm', 'signin', 'authenticate', 'validate', 'reactivate',
        'invoice', 'payment', 'wallet', 'free', 'gift', 'winner', 'prize', 'bonus', 'claim'
    ]
    has_suspicious = 1 if any(word in url_lower for word in suspicious_words) else 0

    typo_brands = [
        'paypai', 'bank-ofamerica', 'apple-support', 'microsoft-update',
        'micro-soft', 'rnicrosoft', 'appIe', 'chase-secure', 'g00gle', 'gooogle', 'amaz0n', 'amz'
    ]
    has_typo = 1 if any(word in url_lower for word in typo_brands) else 0

    safe_brands = [
        'google', 'facebook', 'youtube', 'amazon', 'apple', 'microsoft',
        'netflix', 'github', 'twitter', 'linkedin', 'instagram', 'paypal', 'coinbase',
        'chowdeck', 'paystack', 'jumia', 'kuda', 'flutterwave', 'opay', 'moniepoint',
        'chippercash', 'konga', 'shopee', 'flipkart', 'lazada', 'grab', 'gojek',
        'zomato', 'swiggy', 'paytm', 'mercadolibre', 'nubank', 'rappi', 'ifood',
        'pagseguro', 'revolut', 'monzo', 'n26', 'klarna', 'deliveroo', 'zalando',
        'whatsapp', 'tiktok', 'twitch', 'reddit', 'meta', 'spotify', 'telegram',
        'discord', 'snapchat', 'pinterest', 'roblox', 'canva', 'flickr',
        'skyscanner', 'booking', 'vinted', 'adobe', 'ikea', 'decathlon', 'asos',
        'airbnb', 'bbc', 'cnn', 'nytimes', 'aljazeera', 'mtn', 'airtel', 'glo',
        'safaricom', 'mpesa', 'dstv', 'showmax', 'jiji', 'kikuu', 'gtbank',
        'firstbanknigeria', 'accessbankplc', 'ubagroup', 'stanbicibtc', 'fcmb',
        'fidelitybank', 'ecobank', 'kcb', 'equitybank', 'standardbank', 'nedbank',
        'capitecbank', 'absa', 'fnb'
    ]
    safe_brand_present = 1 if any(f"/{brand}." in url_lower or f".{brand}." in url_lower or f"//{brand}." in url_lower for brand in safe_brands) else 0

    high_risk_tlds = ['.top', '.xyz', '.loan', '.click', '.win', '.vip', '.site', '.online', '.buzz', '.info']
    has_risky_tld = 1 if any(url_lower.endswith(tld) or (tld + '/') in url_lower for tld in high_risk_tlds) else 0

    is_http = 1 if url.startswith('http://') else 0

    ext = tldextract.extract(url)
    domain_name = ext.domain
    entropy = calculate_entropy(domain_name)

    has_at_symbol = 1 if '@' in url else 0

    domain_age_days = -1 if fast_mode else get_domain_age(url)

    return [url_length, dot_count, has_hyphen, has_https, has_suspicious, has_typo, safe_brand_present, has_risky_tld, is_http, entropy, has_at_symbol, domain_age_days]
```

#### 2. entropy calculation

- File: feature_extractor.py
- Lines: 10-16
- Title: entropy calculation
- Purpose: Measures character randomness in extracted domain token.

```python
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy
```

#### 3. suspicious-term logic

- File: feature_extractor.py
- Lines: 45-51
- Title: suspicious-term logic
- Purpose: Flags URLs containing phishing-associated lexical terms.

```python
suspicious_words = [
    'login', 'secure', 'verify', 'account', 'update', 'banking', 'auth',
    'support', 'service', 'helpdesk', 'recovery', 'billing', 'admin', 'security',
    'confirm', 'signin', 'authenticate', 'validate', 'reactivate',
    'invoice', 'payment', 'wallet', 'free', 'gift', 'winner', 'prize', 'bonus', 'claim'
]
has_suspicious = 1 if any(word in url_lower for word in suspicious_words) else 0
```

#### 4. brand typo / known-brand logic

- File: feature_extractor.py
- Lines: 53-75
- Title: brand typo / known-brand logic
- Purpose: Detects typo-brand patterns and known brand presence in URL.

```python
typo_brands = [
    'paypai', 'bank-ofamerica', 'apple-support', 'microsoft-update',
    'micro-soft', 'rnicrosoft', 'appIe', 'chase-secure', 'g00gle', 'gooogle', 'amaz0n', 'amz'
]
has_typo = 1 if any(word in url_lower for word in typo_brands) else 0

safe_brands = [
    'google', 'facebook', 'youtube', 'amazon', 'apple', 'microsoft',
    'netflix', 'github', 'twitter', 'linkedin', 'instagram', 'paypal', 'coinbase',
    'chowdeck', 'paystack', 'jumia', 'kuda', 'flutterwave', 'opay', 'moniepoint',
    'chippercash', 'konga', 'shopee', 'flipkart', 'lazada', 'grab', 'gojek',
    'zomato', 'swiggy', 'paytm', 'mercadolibre', 'nubank', 'rappi', 'ifood',
    'pagseguro', 'revolut', 'monzo', 'n26', 'klarna', 'deliveroo', 'zalando',
    'whatsapp', 'tiktok', 'twitch', 'reddit', 'meta', 'spotify', 'telegram',
    'discord', 'snapchat', 'pinterest', 'roblox', 'canva', 'flickr',
    'skyscanner', 'booking', 'vinted', 'adobe', 'ikea', 'decathlon', 'asos',
    'airbnb', 'bbc', 'cnn', 'nytimes', 'aljazeera', 'mtn', 'airtel', 'glo',
    'safaricom', 'mpesa', 'dstv', 'showmax', 'jiji', 'kikuu', 'gtbank',
    'firstbanknigeria', 'accessbankplc', 'ubagroup', 'stanbicibtc', 'fcmb',
    'fidelitybank', 'ecobank', 'kcb', 'equitybank', 'standardbank', 'nedbank',
    'capitecbank', 'absa', 'fnb'
]
safe_brand_present = 1 if any(f"/{brand}." in url_lower or f".{brand}." in url_lower or f"//{brand}." in url_lower for brand in safe_brands) else 0
```

#### 5. domain-age logic

- File: feature_extractor.py
- Lines: 18-34, 88
- Title: domain-age logic
- Purpose: Computes WHOIS-based domain age and maps into feature vector.

```python
def get_domain_age(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        creation_date = w.creation_date
        if type(creation_date) is list:
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                except:
                    return -1
            return (datetime.now() - creation_date).days
    except Exception:
        pass
    return -1

domain_age_days = -1 if fast_mode else get_domain_age(url)
```

#### 6. final ordered feature-vector return

- File: feature_extractor.py
- Lines: 90
- Title: final ordered feature-vector return
- Purpose: Returns ordered 12-feature model input array.

```python
return [url_length, dot_count, has_hyphen, has_https, has_suspicious, has_typo, safe_brand_present, has_risky_tld, is_http, entropy, has_at_symbol, domain_age_days]
```

### training file

#### 1. ensemble model construction

- File: train_model.py
- Lines: 145-147
- Title: ensemble model construction
- Purpose: Defines tri-model soft-voting classifier.

```python
model = VotingClassifier(estimators=[
    ('rf', rf), ('xgb', xgb_model), ('lr', lr)
], voting='soft')
```

#### 2. dataset loading / preparation

- File: train_model.py
- Lines: 12-44, 100-106
- Title: dataset loading / preparation
- Purpose: Downloads phishing dataset and falls back to local dataset when needed.

```python
def download_raw_dataset():
    print("Downloading curated JPCERTCC phishing dataset for training...")
    all_phish_dfs = []

    for year in range(2024, 2027):
        for month in range(1, 13):
            url = f"https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/{year}/{year}{month:02d}.csv"
            try:
                r = requests.head(url, timeout=5)
                if r.status_code == 200:
                    print(f" -> Fetching data for {year}-{month:02d}...")
                    df = pd.read_csv(url)
                    all_phish_dfs.append(df)
                elif r.status_code in [403, 429]:
                    print("Rate limited by GitHub. Falling back to local data.")
                    return None, 0
            except Exception as e:
                pass

    if all_phish_dfs:
        combined_phish = pd.concat(all_phish_dfs, ignore_index=True)
        url_col = 'URL' if 'URL' in combined_phish.columns else combined_phish.columns[1]
        combined_phish.drop_duplicates(subset=[url_col], inplace=True, ignore_index=True)

        if len(combined_phish) > 25000:
            combined_phish = combined_phish.sample(n=25000, random_state=42).reset_index(drop=True)

        print(f"Sampled {len(combined_phish)} unique phishing URLs for training.")
        return combined_phish, len(combined_phish)
    else:
        print("Failed to download any datasets.")
        return None, 0

def train_model():
    phish_df, phish_count = download_raw_dataset()

    if phish_df is None and os.path.exists('dataset.csv'):
        print("Loading fallback from local dataset.csv")
        df = pd.read_csv('dataset.csv')
```

#### 3. safe-domain or synthetic-data injection

- File: train_model.py
- Lines: 46-98, 108-132
- Title: safe-domain or synthetic-data injection
- Purpose: Generates synthetic benign samples and combines with phishing feature rows.

```python
def generate_synthetic_data(num_samples=2000):
    print(f"Generating {num_samples} highly realistic synthetic Benign URLs...")
    np.random.seed(42)

    safe_data = pd.DataFrame({
        'url_length': np.random.randint(15, 60, num_samples),
        'dot_count': np.random.randint(1, 4, num_samples),
        'has_hyphen': np.random.choice([0, 1], p=[0.8, 0.2], size=num_samples),
        'has_https': np.random.choice([0, 1], p=[0.05, 0.95], size=num_samples),
        'has_suspicious': np.zeros(num_samples, dtype=int),
        'has_typo': np.zeros(num_samples, dtype=int),
        'safe_brand_present': np.zeros(num_samples, dtype=int),
        'has_risky_tld': np.zeros(num_samples, dtype=int),
        'is_http': np.random.choice([1, 0], p=[0.05, 0.95], size=num_samples),
        'entropy': np.random.uniform(2.5, 4.0, num_samples),
        'has_at_symbol': np.zeros(num_samples, dtype=int),
        'domain_age_days': np.random.randint(100, 3000, num_samples),
        'label': np.zeros(num_samples, dtype=int)
    })

    pure_safe = pd.DataFrame({
        'url_length': np.random.randint(12, 35, 15000),
        'dot_count': np.random.choice([1, 2], p=[0.7, 0.3], size=15000),
        'has_hyphen': np.random.choice([0, 1], p=[0.9, 0.1], size=15000),
        'has_https': [1]*15000,
        'has_suspicious': [0]*15000,
        'has_typo': [0]*15000,
        'safe_brand_present': np.random.choice([0, 1], p=[0.5, 0.5], size=15000),
        'has_risky_tld': [0]*15000,
        'is_http': [0]*15000,
        'entropy': np.random.uniform(2.2, 3.8, 15000),
        'has_at_symbol': [0]*15000,
        'domain_age_days': np.random.randint(500, 5000, 15000),
        'label': [0]*15000
    })

    local_business_safe = pd.DataFrame({
        'url_length': np.random.randint(15, 38, 20000),
        'dot_count': np.random.choice([1, 2, 3], p=[0.3, 0.6, 0.1], size=20000),
        'has_hyphen': np.random.choice([0, 1], p=[0.8, 0.2], size=20000),
        'has_https': [1]*20000,
        'has_suspicious': [0]*20000,
        'has_typo': [0]*20000,
        'safe_brand_present': [0]*20000,
        'has_risky_tld': [0]*20000,
        'is_http': [0]*20000,
        'entropy': np.random.uniform(2.8, 4.2, 20000),
        'has_at_symbol': [0]*20000,
        'domain_age_days': np.random.randint(100, 2000, 20000),
        'label': [0]*20000
    })

    return pd.concat([safe_data, pure_safe, local_business_safe], ignore_index=True)

safe_samples_needed = phish_count if phish_count > 0 else 2000
safe_data = generate_synthetic_data(safe_samples_needed)

if phish_df is not None:
    print(f"Extracting features from {phish_count} JPCERTCC phishing URLs (fast_mode for age)...")
    url_col = 'URL' if 'URL' in phish_df.columns else phish_df.columns[1]

    phish_features = phish_df[url_col].dropna().astype(str).apply(lambda x: extract_features(x, fast_mode=True)).tolist()
    feature_cols = [
        'url_length', 'dot_count', 'has_hyphen', 'has_https', 'has_suspicious', 'has_typo',
        'safe_brand_present', 'has_risky_tld', 'is_http', 'entropy', 'has_at_symbol', 'domain_age_days'
    ]
    phishy_data = pd.DataFrame(phish_features, columns=feature_cols)

    # Simulate real phishing domain age (often very recently registered) for fast training
    np.random.seed(42)
    phishy_data['domain_age_days'] = np.random.randint(1, 30, size=len(phishy_data))
    phishy_data['label'] = 1

    print("Combining JPCERTCC Phishing URLs with Synthetic Benign URLs...")
    df = pd.concat([safe_data, phishy_data]).sample(frac=1, random_state=42).reset_index(drop=True)
```

#### 4. model training / fitting

- File: train_model.py
- Lines: 137-153
- Title: model training / fitting
- Purpose: Splits data, trains models, and computes accuracy summary.

```python
print("Using dataset for training...")
X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
xgb_model = XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss')
lr = LogisticRegression(max_iter=2000, random_state=42)

model = VotingClassifier(estimators=[
    ('rf', rf), ('xgb', xgb_model), ('lr', lr)
], voting='soft')

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Tri-Model Ensemble Training Complete. Accuracy: {acc*100:.2f}%")
```

#### 5. model save with joblib

- File: train_model.py
- Lines: 155-156
- Title: model save with joblib
- Purpose: Persists trained ensemble for runtime inference.

```python
joblib.dump(model, 'phishing_model.joblib')
print("Model saved as 'phishing_model.joblib'.")
```

### static/main.js

#### 1. fetch request to /predict

- File: static/main.js
- Lines: 99-103
- Title: fetch request to /predict
- Purpose: Sends URL payload to backend prediction endpoint.

```javascript
const response = await fetch("/predict", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url }),
});
```

#### 2. verdict / confidence rendering

- File: static/main.js
- Lines: 191-194
- Title: verdict / confidence rendering
- Purpose: Updates verdict label and confidence percentage in UI.

```javascript
const isPhishing = data.prediction === "Phishing";
predictionText.textContent = data.prediction;
confidenceText.textContent = `Confidence: ${data.confidence}%`;

predictionText.className =
  "text-5xl font-extrabold mt-4 uppercase transition-all drop-shadow-[0_0_15px_rgba(255,255,255,0.5)]";
```

#### 3. Chart.js rendering code

- File: static/main.js
- Lines: 314-348
- Title: Chart.js rendering code
- Purpose: Renders phishing-vs-safe doughnut chart from confidence.

```javascript
function renderDoughnutChart(isPhishing, confidence) {
  const ctx = document.getElementById("probability-chart").getContext("2d");

  if (doughnutChart) doughnutChart.destroy();

  const phishingProb = isPhishing ? confidence : 100 - confidence;
  const safeProb = isPhishing ? 100 - confidence : confidence;

  doughnutChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Phishing", "Safe"],
      datasets: [
        {
          data: [phishingProb, safeProb],
          backgroundColor: ["#ef4444", "#4ade80"],
          borderWidth: 0,
          hoverOffset: 4,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#e2e8f0" },
        },
      },
    },
  });
}
```

#### 4. threat summary rendering

- File: static/main.js
- Lines: 221-251
- Title: threat summary rendering
- Purpose: Converts threat summary tags into iconized bullet list.

```javascript
if (data.threat_summary && data.threat_summary.length > 0) {
  threatSection.classList.remove("hidden");
  threatList.innerHTML = "";

  data.threat_summary.forEach((t) => {
    const li = document.createElement("li");
    li.className = "flex items-start text-slate-300";

    let iconSvg = "";
    let cleanText = t;

    if (t.startsWith("[PASS]")) {
      cleanText = t.replace("[PASS]", "").trim();
      iconSvg = `<svg class="w-5 h-5 text-green-400 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
    } else if (t.startsWith("[WARN]")) {
      cleanText = t.replace("[WARN]", "").trim();
      iconSvg = `<svg class="w-5 h-5 text-amber-500 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
    } else if (t.startsWith("[FAIL]")) {
      cleanText = t.replace("[FAIL]", "").trim();
      iconSvg = `<svg class="w-5 h-5 text-red-500 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
    } else {
      // Fallback just in case
      iconSvg = `<svg class="w-5 h-5 text-cyan-400 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>`;
    }

    li.innerHTML = `${iconSvg} <span class="pt-0.5">${cleanText}</span>`;
    threatList.appendChild(li);
  });
} else if (threatSection) {
  threatSection.classList.add("hidden");
}
```

#### 5. onboarding modal / localStorage logic

- File: static/main.js
- Lines: 40-53
- Title: onboarding modal / localStorage logic
- Purpose: Shows onboarding once and persists first-visit completion state.

```javascript
function openOnboarding() {
  onboardingModal.classList.remove("hidden");
}

function closeOnboardingModal() {
  onboardingModal.classList.add("hidden");
  localStorage.setItem("secops_visited", "true");
}

if (!localStorage.getItem("secops_visited")) {
  openOnboarding();
}

closeOnboarding.addEventListener("click", closeOnboardingModal);
openAboutBtn.addEventListener("click", openOnboarding);
```

### templates/index.html

#### 1. main input form

- File: templates/index.html
- Lines: 247-271
- Title: main input form
- Purpose: Captures URL input and triggers scan action.

```html
<div class="flex flex-col md:flex-row gap-4">
  <input
    type="text"
    id="url-input"
    placeholder="Type a link here (e.g., google.com or https://paypal.com)"
    class="flex-1 bg-slate-800 text-white rounded-xl px-4 py-3 border border-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 placeholder-slate-500 transition-all text-lg"
    required
  />
  <button
    id="scan-btn"
    class="bg-cyan-600 hover:bg-cyan-500 text-white px-8 py-3 rounded-xl font-semibold transition-all flex items-center justify-center min-w-[150px]"
  >
    <span id="btn-text">Scan Link</span>
    <span
      id="btn-spinner"
      class="hidden ml-2 h-5 w-5 border-2 border-white border-t-transparent rounded-full animate-spin"
    ></span>
  </button>
</div>
```

#### 2. result display section

- File: templates/index.html
- Lines: 274-345
- Title: result display section
- Purpose: Displays verdict and confidence output area.

```html
<section id="results-area" class="hidden">
  <!-- Suggestion / Offline Box -->
  <div
    id="suggestion-box"
    class="hidden mb-6 bg-amber-500/10 border-l-4 border-amber-500 p-5 rounded-r-xl w-full text-left transition-all"
  >
    <h3 class="text-amber-500 font-bold text-lg mb-1 flex items-center">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        class="h-6 w-6 mr-2"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
      <span id="suggestion-title">Site Offline or Unreachable</span>
    </h3>
    <p id="suggestion-text" class="text-slate-300 mb-3 ml-8">
      This URL does not appear to exist or might be currently offline.
    </p>
  </div>

  <div class="text-center mb-8">
    <h2 class="text-2xl font-bold">Threat Assessment</h2>
    <div
      id="prediction-text"
      class="text-5xl font-extrabold mt-4 uppercase drop-shadow-[0_0_15px_rgba(255,255,255,0.5)] transition-all"
    >
      <!-- Text changes dynamically -->
    </div>
    <div
      class="flex items-center justify-center gap-2 mt-2"
      style="position: relative"
    >
      <p id="confidence-text" class="text-slate-400 text-lg"></p>
    </div>
  </div>
</section>
```

#### 3. chart section / canvas

- File: templates/index.html
- Lines: 420-425
- Title: chart section / canvas
- Purpose: Defines Chart.js canvas for probability visualization.

```html
<!-- Doughnut Chart -->
<div
  class="bg-slate-800/50 rounded-2xl p-6 shadow-lg border border-slate-700 flex justify-center items-center"
>
  <canvas id="probability-chart" class="w-full max-w-xs"></canvas>
</div>
```

#### 4. threat summary panel

- File: templates/index.html
- Lines: 427-453
- Title: threat summary panel
- Purpose: Hosts threat analysis list rendered by frontend script.

```html
<!-- Threat Analysis Section (Replaces empty space) -->
<div
  id="threat-analysis-section"
  class="hidden bg-slate-800/50 rounded-2xl p-6 shadow-lg border border-slate-700 flex flex-col text-left"
>
  <h3
    class="text-lg font-bold text-white mb-4 flex items-center border-b border-slate-700 pb-3"
  >
    <svg
      xmlns="http://www.w3.org/2000/svg"
      class="h-5 w-5 mr-2 text-cyan-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
      />
    </svg>
    Threat Analysis Breakdown
  </h3>
  <ul id="threat-list" class="space-y-3 text-sm text-slate-300 mt-2">
    <!-- Javascript injects this -->
  </ul>
</div>
```

#### 5. onboarding modal markup

- File: templates/index.html
- Lines: 112-176
- Title: onboarding modal markup
- Purpose: Defines first-visit walkthrough modal UI.

```html
<!-- First-Visit Onboarding Modal -->
<div
  id="onboarding-modal"
  class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[100] hidden"
>
  <div
    class="bg-slate-800 border border-slate-700 rounded-2xl p-8 max-w-md mx-4 shadow-2xl animate-scale-in"
  >
    <div class="text-center mb-6">
      <svg
        class="w-16 h-16 mx-auto text-cyan-400 mb-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
        ></path>
      </svg>
      <h2 class="text-2xl font-bold text-white mb-2">Welcome to SecOps</h2>
      <p class="text-slate-400 text-sm mb-6">
        Your AI-powered URL threat analyzer
      </p>
    </div>

    <div class="space-y-4 mb-8">
      <div class="flex gap-3">
        <span class="text-cyan-400 font-bold text-lg flex-shrink-0">1.</span>
        <p class="text-slate-300 text-sm">
          <strong>Paste Any Link:</strong> Submit URLs you're unsure about—from
          emails, messages, or ads.
        </p>
      </div>
    </div>

    <button
      id="close-onboarding"
      class="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-3 rounded-lg transition-all"
    >
      Get Started
    </button>
  </div>
</div>
```

## SECTION 2 — MODEL / TESTING RESULTS

### Accuracy

- Value: Runtime-calculated value
- Source file: evaluate_model.py
- Context: Real-world accuracy is computed after OpenPhish + tricky URL test loop.
- Exact source text:

```python
accuracy = (caught / len(test_urls)) * 100 if test_urls else 0
print(f"Real-World Accuracy: {accuracy:.2f}%\n")
```

### Precision

NOT FOUND IN CURRENT REPO

### Recall

NOT FOUND IN CURRENT REPO

### Confusion matrix

NOT FOUND IN CURRENT REPO

## SECTION 3 — OPTIONAL RESULTS

### F1-score

NOT FOUND IN CURRENT REPO

### Classification report

NOT FOUND IN CURRENT REPO

### ROC-AUC

NOT FOUND IN CURRENT REPO

### Sample test cases or sample prediction outputs

- Value: Available
- Source file: evaluate_model.py
- Context: Hardcoded tricky URL test cases used in evaluation script.
- Exact source text:

```python
tricky_urls = [
    "https://bank-ofamerica.com/login",
    "https://login.paypaI.com/secure"
]
```

- Value: Available
- Source file: logs/scan_history.log
- Context: Logged sample prediction outputs from scanner runs.
- Exact source text:

```text
2026-03-27 02:50:18 | URL: http://www.g00gle-support-ticket.xyz/auth | Prob: 99.0% | Status: Phishing
2026-03-27 02:50:22 | URL: https://amazon.com.customer-service-login.top/verify | Prob: 99.0% | Status: Phishing
2026-03-27 02:50:41 | URL: http://t.me/free_crypto_trading_bot_xxyz | Prob: 99.0% | Status: Phishing
2026-03-27 06:21:33 | URL: https://g00gle.com | Prob: 95.0% | Status: Phishing
```
