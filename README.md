# 🛡️ SecOps Phishing URL Scanner

Welcome to the **SecOps Phishing Detection** tool! This is a smart web application designed to protect you from fake, malicious websites that try to steal your information (like fake PayPal or fake Bank of America pages).

## What does it do?

It acts as a digital security guard. Before you click or visit a suspicious link, you can paste it into our scanner. Behind the scenes, an Artificial Intelligence (AI) immediately evaluates the link and tells you whether it's safe to visit or if it's a dangerous "phishing" trap.

If the link is totally safe, the tool will even give you a polite little bio about the site and offer you a safe button to be redirected there!

## Features

- **Instant AI Scanning:** No waiting around. The AI analyzes 9 custom-engineered features of any URL in milliseconds (like Unsecured HTTP and high-risk domains like `.top`).
- **Real-World Threat Intelligence:** The AI is trained on 7 years of live, real-world phishing data tracking (2020-2026) directly integrated from JPCERTCC's threat feed.
- **Offline Domain & Typo Detection:** Not only does the scanner detect if a scam link has been taken down (preventing fake "Safe to Proceed" buttons), but its built-in typo engine (using fuzzy logic) will realize if you meant to type a real site (e.g., `jumiia.com` -> catches it, marks it as a threat, and asks "Did you mean to visit Jumia?").
- **Zero-Trust Overrides:** Features an architecture that actively overrides AI "hallucinations". If a URL uses a `.xyz` domain or triggers the Typo-Squatting engine, it hardcodes an instantaneous 95-99% Phishing flag.
- **False-Positive Mitigation:** Includes advanced synthetic "Pure Safe" arrays to ensure legitimate short-domains (like google.com) aren't mistakenly penalized.
- **GitHub Optimized:** Aggregates a massive real-world dataset but strictly caps output to 25,000 randomized dynamic URLs to easily meet GitHub's <100MB limits.
- **Smart Formatting & Shortcuts:** Forget the https://? Don't worry, the app fixes messy links for you automatically. Now supports keyboard "Enter" submissions!
- **Interactive UI & Auto-Rotating Cyber Tips:** Hover over the Confidence Score tooltip to learn about the AI's math, accompanied by a dynamic security tip that changes every 5 seconds!
- **Light & Dark Mode:** Easy on the eyes, toggle between themes with a single click.

## How to use this project

To run this on your own machine, you just need Python installed!

**1. Install the tools**
Open your terminal and install the required dependencies:

`ash
pip install -r requirements.txt
`

**2. Train the AI Brain**
We need to teach the AI what fake websites look like. Run the training script:

`ash
python train_model.py
`

_(This script connects to the JPCERTCC GitHub repository, downloads verified phishing URLs from 2020-2026, synthesizes a matching balanced dataset of safe URLs, and trains the Random Forest system organically)._

**3. Start the Web Server**
Launch the actual website:

`ash
python app.py
`

Now, simply open your web browser and go to: **http://127.0.0.1:5000**

---

_Created as a lightweight, lightning-fast Final Year Presentation Project._
