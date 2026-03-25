def extract_features(url):
    url_lower = url.lower()
    
    # 1. URL Length (Phishing usually longer)
    url_length = len(url)
    
    # 2. Count of dots '.' (Subdomains)
    dot_count = url.count('.')
    
    # 3. Presence of hyphen '-' (Domain squatting)
    has_hyphen = 1 if '-' in url else 0
    
    # 4. Presence of https
    has_https = 1 if url.startswith('https://') else 0
    
    # 5. [NEW] Suspicious keywords
    suspicious_words = [
        'login', 'secure', 'verify', 'account', 'update', 'banking', 'auth',
        'support', 'service', 'helpdesk', 'recovery', 'billing', 'admin', 'security',
        'confirm', 'signin', 'authenticate', 'validate', 'reactivate',
        'invoice', 'payment', 'wallet', 'free', 'gift', 'winner', 'prize', 'bonus', 'claim'
    ]
    has_suspicious = 1 if any(word in url_lower for word in suspicious_words) else 0

    # 6. [NEW] Targeted Brand Typos / Squats
    typo_brands = [
        'paypai', 'bank-ofamerica', 'apple-support', 'microsoft-update',
        'micro-soft', 'rnicrosoft', 'appIe', 'chase-secure', 'g00gle', 'gooogle', 'amaz0n', 'amz'
    ]
    has_typo = 1 if any(word in url_lower for word in typo_brands) else 0

    # 7. [NEW] Known Safe Brand Name (forces the model to trust major domains)
    safe_brands = [
        'google', 'facebook', 'youtube', 'amazon', 'apple', 'microsoft',
        'netflix', 'github', 'twitter', 'linkedin', 'instagram', 'paypal', 'coinbase',
        'chowdeck', 'paystack', 'jumia', 'kuda', 'flutterwave', 'opay', 'moniepoint', 
        'chippercash', 'konga', 'shopee', 'flipkart', 'lazada', 'grab', 'gojek', 
        'zomato', 'swiggy', 'paytm', 'mercadolibre', 'nubank', 'rappi', 'ifood', 
        'pagseguro', 'revolut', 'monzo', 'n26', 'klarna', 'deliveroo', 'zalando'
    ]
    safe_brand_present = 1 if any(f"/{brand}." in url_lower or f".{brand}." in url_lower or f"//{brand}." in url_lower for brand in safe_brands) else 0

    # 8. [NEW] High-risk Top Level Domains (gTLDs often used by scammers)
    high_risk_tlds = ['.top', '.xyz', '.loan', '.click', '.win', '.vip', '.site', '.online', '.buzz', '.info']
    has_risky_tld = 1 if any(url_lower.endswith(tld) or (tld + '/') in url_lower for tld in high_risk_tlds) else 0

    # 9. [NEW] Checking for unencrypted HTTP
    is_http = 1 if url.startswith('http://') else 0

    return [url_length, dot_count, has_hyphen, has_https, has_suspicious, has_typo, safe_brand_present, has_risky_tld, is_http]
