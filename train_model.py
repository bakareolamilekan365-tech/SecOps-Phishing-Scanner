import pandas as pd
import numpy as np
import requests
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from feature_extractor import extract_features

def download_raw_dataset():
    print("Downloading curated JPCERTCC phishing dataset for training...")
    all_phish_dfs = []
    
    # We will sample from 2024 to 2026, keeping it lightweight to prevent download timeouts
    for year in range(2024, 2027):
        for month in range(1, 13):
            url = f"https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/{year}/{year}{month:02d}.csv"
            try:
                r = requests.head(url)
                if r.status_code == 200:
                    print(f" -> Fetching data for {year}-{month:02d}...")
                    df = pd.read_csv(url)
                    all_phish_dfs.append(df)
            except Exception as e:
                pass 

    if all_phish_dfs:
        combined_phish = pd.concat(all_phish_dfs, ignore_index=True)
        url_col = 'URL' if 'URL' in combined_phish.columns else combined_phish.columns[1]
        combined_phish.drop_duplicates(subset=[url_col], inplace=True, ignore_index=True)
        
        # Take a random sample of 25,000 URLs to ensure the final output file stays lightweight!
        if len(combined_phish) > 25000:
            combined_phish = combined_phish.sample(n=25000, random_state=42).reset_index(drop=True)
            
        print(f"Sampled {len(combined_phish)} unique phishing URLs for training.")
        return combined_phish, len(combined_phish)
    else:
        print("Failed to download any datasets.")
        return None, 0

def generate_synthetic_data(num_samples=2000):
    print(f"Generating {num_samples} highly realistic synthetic Benign URLs...")
    np.random.seed(42)

    # Shorter length, fewer dots, fewer hyphens, mostly https, no suspicious words, no typos
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
        'label': np.zeros(num_samples, dtype=int) # Benign
    })

    # Inject ultra-pure safe domains (like google.com, facebook.com, or random safe small businesses)
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
        'label': [0]*15000 # Benign
    })

    # Specifically inject short domains without big brands to represent local businesses
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
        'label': [0]*20000 # Benign
    })

    return pd.concat([safe_data, pure_safe, local_business_safe], ignore_index=True)

def train_model():
    phish_df, phish_count = download_raw_dataset()

    # We balance the benign synthetic dataset to match our phising data pool
    safe_samples_needed = phish_count if phish_count > 0 else 2000
    safe_data = generate_synthetic_data(safe_samples_needed)

    if phish_df is not None:
        print(f"Extracting features from {phish_count} JPCERTCC phishing URLs (this might take a moment)...")
        url_col = 'URL' if 'URL' in phish_df.columns else phish_df.columns[1]

        phish_features = phish_df[url_col].dropna().astype(str).apply(extract_features).tolist()
        phishy_data = pd.DataFrame(phish_features, columns=[
            'url_length', 'dot_count', 'has_hyphen', 'has_https', 'has_suspicious', 'has_typo', 'safe_brand_present', 'has_risky_tld', 'is_http'
        ])
        phishy_data['label'] = 1 # Phishing

        print("Combining JPCERTCC Phishing URLs with Synthetic Benign URLs...")
        df = pd.concat([safe_data, phishy_data]).sample(frac=1, random_state=42).reset_index(drop=True)
    else:
        print("Using ONLY synthetic benign data (Download failed).")
        df = safe_data

    # Export a highly-curated, Github-ready master file.
    df.to_csv('dataset.csv', index=False)
    print("Exported safe, GitHub-ready 'dataset.csv' size:", len(df), "rows.")

    print("Using dataset for training...")
    X = df.drop('label', axis=1)
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model Training Complete. Accuracy: {acc*100:.2f}%")

    joblib.dump(model, 'phishing_model.joblib')
    print("Model saved as 'phishing_model.joblib'.")

if __name__ == "__main__":
    train_model()
