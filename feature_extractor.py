import math
import re
import whois
import tldextract
from datetime import datetime
from urllib.parse import urlparse
import warnings

warnings.filterwarnings("ignore", module="whois")

# Exact domains that should not be penalized by generic lexical terms.
EXACT_SAFE_DOMAIN_OVERRIDES = {
    'behance.net',
    'skyscanner.net'
}

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

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

def extract_features(url, fast_mode=False):
    url_lower = url.lower()
    ext = tldextract.extract(url)
    registrable_domain = f"{ext.domain}.{ext.suffix}".strip('.').lower()
    host_for_flags = ext.fqdn.lower() if ext.fqdn else registrable_domain
    path_and_query = urlparse(url).path.lower()
    is_exact_safe_override = registrable_domain in EXACT_SAFE_DOMAIN_OVERRIDES

    url_length = len(url)
    dot_count = url.count('.')
    has_hyphen = 1 if '-' in host_for_flags else 0
    has_https = 1 if url.startswith('https://') else 0

    suspicious_words = [
        'login', 'secure', 'verify', 'account', 'update', 'banking', 'auth',
        'support', 'service', 'helpdesk', 'recovery', 'billing', 'admin', 'security',
        'confirm', 'signin', 'authenticate', 'validate', 'reactivate',
        'invoice', 'payment', 'wallet', 'free', 'gift', 'winner', 'prize', 'bonus', 'claim'
    ]
    lexical_surface = f"{host_for_flags}{path_and_query}"
    has_suspicious = 1 if any(word in lexical_surface for word in suspicious_words) else 0

    typo_brands = [
        'paypai', 'bank-ofamerica', 'apple-support', 'microsoft-update',
        'micro-soft', 'rnicrosoft', 'appIe', 'chase-secure', 'g00gle', 'gooogle', 'amaz0n', 'amz'
    ]
    has_typo = 1 if any(word in lexical_surface for word in typo_brands) else 0

    if is_exact_safe_override:
        has_suspicious = 0
        has_typo = 0

    safe_brands = [
        'google', 'facebook', 'youtube', 'amazon', 'apple', 'microsoft',
        'netflix', 'github', 'twitter', 'linkedin', 'instagram', 'paypal', 'coinbase',
        'chowdeck', 'paystack', 'jumia', 'kuda', 'flutterwave', 'opay', 'moniepoint',
        'chippercash', 'konga', 'shopee', 'flipkart', 'lazada', 'grab', 'gojek',
        'zomato', 'swiggy', 'paytm', 'mercadolibre', 'nubank', 'rappi', 'ifood',
        'pagseguro', 'revolut', 'monzo', 'n26', 'klarna', 'deliveroo', 'zalando',
        'whatsapp', 'tiktok', 'twitch', 'reddit', 'meta', 'spotify', 'telegram',
        'discord', 'snapchat', 'pinterest', 'roblox', 'canva', 'behance', 'flickr',
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

    domain_name = ext.domain
    entropy = calculate_entropy(domain_name)

    has_at_symbol = 1 if '@' in url else 0

    domain_age_days = -1 if fast_mode else get_domain_age(url)

    return [url_length, dot_count, has_hyphen, has_https, has_suspicious, has_typo, safe_brand_present, has_risky_tld, is_http, entropy, has_at_symbol, domain_age_days]
