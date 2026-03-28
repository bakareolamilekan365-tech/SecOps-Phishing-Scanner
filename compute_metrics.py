"""
Evaluation metrics for the SecOps Phishing Scanner ensemble model.

This script is read-only with respect to existing repository code.
It loads the pre-trained model (phishing_model.joblib) and the committed
dataset (dataset.csv), replicates the exact 80/20 test split that was
used during training (random_state=42), and computes:

  - Accuracy
  - Precision  (macro, weighted, and per-class)
  - Recall     (macro, weighted, and per-class)
  - F1-score   (macro, weighted, and per-class)
  - Confusion Matrix
  - Full Classification Report
  - ROC-AUC

Dataset split : 80 % train / 20 % test  (random_state=42)
Class labels  : 0 = Safe,  1 = Phishing

Reproducibility
---------------
  pip install -r requirements.txt
  python compute_metrics.py
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

# ---------------------------------------------------------------------------
# 1. Load data & model
# ---------------------------------------------------------------------------
print("=" * 60)
print("  SecOps Phishing Scanner — Model Evaluation Report")
print("=" * 60)

df = pd.read_csv("dataset.csv")
model = joblib.load("phishing_model.joblib")

print(f"\nDataset  : dataset.csv  ({len(df):,} rows)")
print(f"Model    : phishing_model.joblib  (VotingClassifier)")

# ---------------------------------------------------------------------------
# 2. Reproduce the exact train/test split used during training
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "url_length", "dot_count", "has_hyphen", "has_https",
    "has_suspicious", "has_typo", "safe_brand_present", "has_risky_tld",
    "is_http", "entropy", "has_at_symbol", "domain_age_days",
]

X = df[FEATURE_COLS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\nSplit    : 80 % train ({len(X_train):,} samples) / "
      f"20 % test ({len(X_test):,} samples)")
print(f"Classes  : 0 = Safe  |  1 = Phishing")
print(f"Test-set class distribution:")
print(f"  Safe     (0) : {(y_test == 0).sum():>6,}")
print(f"  Phishing (1) : {(y_test == 1).sum():>6,}")

# ---------------------------------------------------------------------------
# 3. Generate predictions
# ---------------------------------------------------------------------------
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]   # probability of class 1

# ---------------------------------------------------------------------------
# 4. Compute metrics
# ---------------------------------------------------------------------------
accuracy  = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)
roc_auc   = roc_auc_score(y_test, y_prob)
cm        = confusion_matrix(y_test, y_pred)
report    = classification_report(
                y_test, y_pred,
                target_names=["Safe (0)", "Phishing (1)"],
                zero_division=0,
            )

# ---------------------------------------------------------------------------
# 5. Print report
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("  CORE METRICS  (weighted averages)")
print("=" * 60)
print(f"  Accuracy  : {accuracy * 100:.4f} %")
print(f"  Precision : {precision * 100:.4f} %")
print(f"  Recall    : {recall * 100:.4f} %")
print(f"  F1-score  : {f1 * 100:.4f} %")
print(f"  ROC-AUC   : {roc_auc:.6f}")

print("\n" + "=" * 60)
print("  PER-CLASS METRICS")
print("=" * 60)
for label_idx, label_name in enumerate(["Safe (0)", "Phishing (1)"]):
    p = precision_score(y_test, y_pred, pos_label=label_idx, average="binary", zero_division=0)
    r = recall_score(y_test, y_pred, pos_label=label_idx, average="binary", zero_division=0)
    f = f1_score(y_test, y_pred, pos_label=label_idx, average="binary", zero_division=0)
    support = int((y_test == label_idx).sum())
    print(f"\n  {label_name}")
    print(f"    Precision : {p * 100:.4f} %")
    print(f"    Recall    : {r * 100:.4f} %")
    print(f"    F1-score  : {f * 100:.4f} %")
    print(f"    Support   : {support:,}")

print("\n" + "=" * 60)
print("  CONFUSION MATRIX")
print("  Rows = Actual  |  Columns = Predicted")
print("  Labels: [Safe (0), Phishing (1)]")
print("=" * 60)
tn, fp, fn, tp = cm.ravel()
print(f"\n  [[{tn:6,}  {fp:6,}]   <- Actual Safe")
print(f"   [{fn:6,}  {tp:6,}]]  <- Actual Phishing")
print(f"\n  True  Negatives (TN) : {tn:,}")
print(f"  False Positives (FP) : {fp:,}")
print(f"  False Negatives (FN) : {fn:,}")
print(f"  True  Positives (TP) : {tp:,}")

print("\n" + "=" * 60)
print("  FULL CLASSIFICATION REPORT")
print("=" * 60)
print(report)

print("=" * 60)
print("  MACRO / WEIGHTED AVERAGES SUMMARY")
print("=" * 60)
for avg in ("macro", "weighted"):
    p_avg = precision_score(y_test, y_pred, average=avg, zero_division=0)
    r_avg = recall_score(y_test, y_pred, average=avg, zero_division=0)
    f_avg = f1_score(y_test, y_pred, average=avg, zero_division=0)
    print(f"\n  {avg.capitalize()} average")
    print(f"    Precision : {p_avg * 100:.4f} %")
    print(f"    Recall    : {r_avg * 100:.4f} %")
    print(f"    F1-score  : {f_avg * 100:.4f} %")

print("\n" + "=" * 60)
print("  ROC-AUC DETAIL")
print("=" * 60)
print(f"  AUC value : {roc_auc:.6f}")
if roc_auc >= 0.99:
    tier = "Excellent  (near-perfect discrimination)"
elif roc_auc >= 0.95:
    tier = "Very good"
elif roc_auc >= 0.90:
    tier = "Good"
else:
    tier = "Fair"
print(f"  Tier      : {tier}")

print("\n" + "=" * 60)
print("  NOTES / ASSUMPTIONS")
print("=" * 60)
print("""
  1. Dataset  : dataset.csv (committed to repo, 85,000 rows).
     This is the same file loaded by train_model.py when
     the online JPCERTCC download is unavailable.

  2. Split    : train_test_split(test_size=0.2, random_state=42)
     identical to the split in train_model.py (line 139).

  3. Model    : phishing_model.joblib loaded with joblib.load().
     No re-training is performed.

  4. Features : 12-dimensional numeric vector (see FEATURE_COLS).

  5. Metrics computed on the held-out TEST split (20 %, ~17 000
     samples) which was never seen during model fitting.
""")
print("=" * 60)
print("  END OF REPORT")
print("=" * 60)
