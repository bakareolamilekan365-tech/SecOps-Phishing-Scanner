# SecOps Technical Brief: Lightweight Phishing Detection Architecture

### 1. Data Pipeline

- **Malicious Dataset Injection:** Dynamically fetches live, real-world zero-day phishing feeds (from 2024 to 2026) directly from the JPCERTCC GitHub repository.
- **Data Normalization:** Parses CSV files, drops duplicate URLs, and caps the randomized sample to exactly 25,000 domains to maintain a highly lightweight memory footprint.
- **Synthetic Benign Baseline:** Generates a mirrored 1:1 volume of "Benign" URLs synthetically using `pandas` and `numpy`.
- **False-Positive Mitigation Generation:** Injects 15,000 "Pure Safe" arrays (simulating global brands) and 20,000 "Local Business" arrays (simulating short subdomains with limited tracking) to train the model out of falsely flagging unbranded legit business links.

### 2. Feature Engineering

The heuristic engine (`feature_extractor.py`) vectorizes raw URL strings into a 9-feature numerical matrix:

- **URL Length:** Continuous integer; penalizes abnormally long strings.
- **Subdomain Count:** Counts `.` delimiters to catch deep-nested malicious routing.
- **Hyphenation Checks:** Binary flag for domain squatting (`-`).
- **Protocol Validation:** Binary flag strictly checking for valid `https://`.
- **Suspicious Keywords:** Binary flag checking for urgency/billing keywords (e.g., `login`, `secure`, `verify`).
- **Brand Typo-Squatting:** Binary flag triggered by hardcoded homograph arrays (e.g., `paypai`).
- **Safe Brand Presence:** Binary flag mapping highly-trusted Global and Regional domains to anchor safe scores.
- **High-Risk TLDs:** Binary flag targeting notorious top-level domains (`.top`, `.xyz`, `.loan`).
- **Unencrypted Traffic:** Binary flag that instantly flags explicit `http://` protocols.

### 3. Model Specifications

- **Algorithm:** `RandomForestClassifier` from Scikit-Learn.
- **Hyperparameters:** `n_estimators=100`, `random_state=42`.
- **Implementation Rationale:** A Random Forest was explicitly chosen over Logistic Regression or SVMs due to its ability to handle disjointed, non-linear categorical thresholds efficiently (e.g., evaluating high dot-counts in correlation with missing HTTPS) without requiring heavy data scaling or intensive neural network overhead.

### 4. System Architecture

- **API Layer:** Built on a Python Flask WSGI backend utilizing a single `POST /predict` REST endpoint.
- **Offline/Dead Link Interception:** Flask performs an instantaneous `requests.head()` ping with a 3-second timeout. It catches `SSLError` and `RequestException` blocks, appending an `is_live: False` flag to prevent the frontend from rendering "Proceed Safely" buttons for dead mock URLs.
- **Zero-Trust Hardcoded Overrides:** Before the response is returned, the backend actively filters the AI's probability score. If the URL triggers a known typo or utilizes a `.xyz/.top` TLD, the code bypasses the Machine Learning result and hardcodes a **95% to 99% Phishing** threat flag to correct AI hallucinations.

### 5. Technology Stack

- **Python:** Core backend and data-science execution environment.
- **Scikit-learn:** Responsible for Machine Learning model training and probability inference (`predict_proba`).
- **Pandas & NumPy:** Dataset structuring, mathematical distribution, and synthetic data generation.
- **Joblib:** Lightweight model serialization and persistent state loading (`phishing_model.joblib`).
- **Flask:** Lightweight Web API framework to bridge the ML intelligence and the client browser.
- **Requests:** Network tool to execute pre-flight connectivity and SSL certificate validation pings.
- **TLDExtract:** Context engine library used to natively deconstruct TLD matrices and generate dynamic Safe Link "Bios".
- **Difflib:** Built-in Python library for algorithmic string matching (fuzzy logic at `0.72` cutoff) to detect typo-domains.
- **JavaScript (Vanilla) & Tailwind CSS:** Frontend logic (Fetch APIs) and mobile-responsive, dark-mode/light-mode UI state generation.
- **Chart.js:** Renders the dynamic visual Threat Assessment doughnut graph based on probability confidences.
- **Ngrok & Render:** Infrastructure utilized for local DNS tunneling and production cloud hosting.

### 6. Implementation Workflow

1.  **Ingest:** User submits a raw URL string via the frontend UI.
2.  **Sanitize:** Vanilla JS and Flask collaboratively auto-prepend `https://` if the protocol is missing.
3.  **Validate:** Flask executes a `HEAD` request to verify SSL integrity and server availability.
4.  **Match:** `difflib` parses the naked domain against a dictionary of valid `KNOWN_BRANDS` to detect typo-squats.
5.  **Vectorize:** `extract_features` maps the URL into a 9-column numerical matrix.
6.  **Infer:** The pre-trained Random Forest model ingests the matrix and returns an algorithmic `Phishing | Safe` probability.
7.  **Override:** Script performs a Zero-Trust constraint check; forces Phishing flag if heavily malicious traits are found regardless of AI output.
8.  **Respond:** JSON payload (`prediction`, `confidence`, `suggested_site`, `is_live`, `bio`) is returned.
9.  **Render:** DOM manipulate hides/shows Warning suggestion boxes, plots the Chart.js probability, and conditionally allows redirection only if the site is verified secure and online.
