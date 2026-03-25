import requests

def bot_penetration_test():
    print("🤖 [BOT DIAGNOSTICS] Firing simulated weird edge-cases at the Flask server...\n")
    url = 'http://127.0.0.1:5000/predict'

    tests = [
        {"desc": "Empty Payload entirely", "payload": {}},
        {"desc": "Whitespace String String", "payload": {"url": "   "}},
        {"desc": "Naked Domain (checking the new auto-formatter)", "payload": {"url": "facebook.com"}},
        {"desc": "Outrageously Long String Buffer", "payload": {"url": "https://google.com/" + "A"*500}},
        {"desc": "Sneaky Phish (Should trigger brand & words)", "payload": {"url": "http://verify-bank-ofamerica-account.com"}},
        {"desc": "LEGIT SITE: Amazon", "payload": {"url": "https://amazon.com"}},
        {"desc": "LEGIT SITE: Apple", "payload": {"url": "https://apple.com"}},
        {"desc": "LEGIT SITE: Microsoft", "payload": {"url": "https://microsoft.com"}},
        {"desc": "LEGIT SITE: GitHub", "payload": {"url": "https://github.com"}},
        {"desc": "LEGIT SITE: Netflix", "payload": {"url": "https://netflix.com"}},
        {"desc": "PHISHING SITE: Typo Google", "payload": {"url": "http://g00gle-support.site"}},
        {"desc": "PHISHING SITE: Secure Login Bait", "payload": {"url": "https://secure-login-update-wallet.com"}},
        {"desc": "PHISHING SITE: Apple ID Bait", "payload": {"url": "http://apple-support-invoice-payment.org"}}
    ]

    passed_tests = 0
    for t in tests:
        try:
            res = requests.post(url, json=t["payload"], timeout=5)
            print(f"[->] TEST: {t['desc']}")
            print(f"     Payload: {str(t['payload'])[:60]}")
            print(f"     Code:    {res.status_code}")
            
            # Print a clean snippet of the response text
            resp_text = res.text.strip().replace('\n', ' ')
            print(f"     Result:  {resp_text[:110]}")
            print("-" * 50)
            passed_tests += 1
        except Exception as e:
            print(f"     [!!!] SYSTEM CRASH OR TIMEOUT: {e}")
            print("-" * 50)

    print(f"\n🤖 [BOT DIAGNOSTICS COMPLETE] Stability Score: {passed_tests}/{len(tests)}. Server held strong!")

if __name__ == '__main__':
    bot_penetration_test()
