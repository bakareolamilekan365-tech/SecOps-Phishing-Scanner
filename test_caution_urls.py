#!/usr/bin/env python3
import requests
import json

endpoint = 'https://secops-phishing-scanner-feature.onrender.com/predict'

# Test URLs that might trigger Caution verdict
test_urls = [
    'https://behance.net',           # Known brand (should be Safe now)
    'https://paypal.net',             # Known brand on suspicious TLD 
    'https://netflix-update.net',     # Typo on known brand
    'https://microsoft-security.net', # Typo on known brand
    'https://apple-support-verify.net', # Brand typo with suspicious path
]

print("Testing Caution Verdict on Live Demo Endpoint\n")
print(f"{'URL':<45} {'Verdict':<12} {'Confidence'}")
print("-" * 70)

for url in test_urls:
    try:
        resp = requests.post(endpoint, json={'url': url}, timeout=10)
        data = resp.json()
        verdict = data.get('prediction', 'Unknown')
        confidence = data.get('confidence', 0)
        print(f"{url:<45} {verdict:<12} {confidence}%")
    except Exception as e:
        print(f"{url:<45} {'ERROR':<12} {str(e)[:20]}")

print("\n✅ Test complete. Check if Caution verdicts appear for typosquatted known brands.")
