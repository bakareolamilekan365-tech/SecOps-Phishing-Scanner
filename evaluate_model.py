import requests
import joblib
import numpy as np
import warnings
from feature_extractor import extract_features

# Suppress scikit-learn warnings for cleaner output
warnings.filterwarnings('ignore')

def test_on_real_phishing_db():
    print("\n[+] Loading Trained Model...")
    try:
        model = joblib.load('phishing_model.joblib')
    except FileNotFoundError:
        print("[-] Error: phishing_model.joblib not found.")
        return

    # User's tricky URLs
    tricky_urls = [
        "https://bank-ofamerica.com/login",
        "https://login.paypaI.com/secure"
    ]

    print("[+] Fetching live phishing dataset from OpenPhish feed...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get('https://openphish.com/feed.txt', headers=headers, timeout=10)
        openphish_urls = [u for u in response.text.split('\n') if u.strip()]
        print(f"[+] Downloaded {len(openphish_urls)} active phishing URLs.")
    except Exception as e:
        print(f"[-] Failed to fetch OpenPhish database: {e}")
        openphish_urls = []

    # Combine test set (Tricky User URLs + Top 30 real ones)
    test_urls = tricky_urls + openphish_urls[:30]
    
    caught = 0
    missed = 0

    print("\n" + "="*90)
    print(f"{'URL':<60} | {'PREDICTION':<10} | {'CONFIDENCE'}")
    print("="*90)
    
    for url in test_urls:
        features = extract_features(url, fast_mode=True)
        features_array = np.array(features).reshape(1, -1)
        
        pred = model.predict(features_array)[0]
        prob = model.predict_proba(features_array)[0]
        
        prediction = "Phishing" if pred == 1 else "Safe"
        conf = round(prob[pred] * 100, 2)
        
        if prediction == "Phishing":
            caught += 1
            pred_text_color = "\033[91m" + prediction + "\033[0m" # Red
        else:
            missed += 1
            pred_text_color = "\033[92m" + prediction + "\033[0m" # Green (False Negative in this case)
            
        print(f"{url[:58]:<60} | {pred_text_color:<19} | {conf}%")

    print("="*90)
    print("\n[!] --- DIAGNOSTIC RESULTS ---")
    print(f"Total Phishing URLs Tested: {len(test_urls)}")
    print(f"Model Caught (True Positives): {caught}")
    print(f"Model Missed (False Negatives): {missed}")
    
    accuracy = (caught / len(test_urls)) * 100 if test_urls else 0
    print(f"Real-World Accuracy: {accuracy:.2f}%\n")

if __name__ == "__main__":
    test_on_real_phishing_db()
