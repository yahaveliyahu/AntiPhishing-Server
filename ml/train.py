"""
train.py
========
Trains the XGBoost phishing detection model.

What this file does, step by step:
    1. Loads malicious_phish.csv with Pandas
    2. Converts labels to binary (0 = safe, 1 = malicious)
    3. Runs feature_extractor on every URL to compute 52 features
    4. Splits data: 80% training, 20% testing
    5. Trains XGBoost model on the training set
    6. Saves the trained model to model.pkl

Run this file ONCE:
    python train.py

After it finishes, model.pkl will exist and is ready to use.
Training takes approximately 3-10 minutes depending on your computer.
"""

import os
import time
import joblib
import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from feature_extractor import extract_features

# ── Configuration ─────────────────────────────────────────────────────────────

CSV_PATH   = os.path.join(os.path.dirname(__file__), "malicious_phish.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# How many URLs to process. Use None to process all 651,191.
# Use a smaller number (e.g. 50000) for a quick test run first.
SAMPLE_SIZE = None  # Change to 50000 for a quick test

# ── Step 1: Load the dataset ──────────────────────────────────────────────────

print("=" * 60)
print("AntiPhishing — XGBoost Model Training")
print("=" * 60)
print()
print("Step 1: Loading dataset...")

df = pd.read_csv(CSV_PATH)
df['source'] = 'kaggle'
print(f"  Loaded {len(df):,} URLs from Kaggle dataset")
print(f"  Columns: {list(df.columns)}")

# Also load MongoDB export if it exists
mongodb_csv = os.path.join(os.path.dirname(__file__), "mongodb_urls.csv")
if os.path.exists(mongodb_csv):
    df_mongo = pd.read_csv(mongodb_csv)
    # Tag MongoDB domains so we can give them reduced weight during training
    # Plain domains (malicious_domains collection) have no path and confuse the model
    # They get 0.5x weight — they contribute but do not dominate
    df_mongo['source'] = 'mongodb'
    print(f"  Loaded {len(df_mongo):,} URLs from MongoDB export")
    df = pd.concat([df, df_mongo], ignore_index=True)
else:
    print("  No mongodb_urls.csv found — run export_mongodb.py first")

# Load safe URLs (original 253)
safe_csv = os.path.join(os.path.dirname(__file__), "safe_urls.csv")
if os.path.exists(safe_csv):
    df_safe = pd.read_csv(safe_csv)
    print(f"  Loaded {len(df_safe):,} realistic safe URLs")
    df = pd.concat([df, df_safe], ignore_index=True)

# Load expanded safe URLs (1,908 from top domains)
safe_exp_csv = os.path.join(os.path.dirname(__file__), "safe_urls_expanded.csv")
if os.path.exists(safe_exp_csv):
    df_safe_exp = pd.read_csv(safe_exp_csv)
    print(f"  Loaded {len(df_safe_exp):,} expanded safe URLs")
    df = pd.concat([df, df_safe_exp], ignore_index=True)

# Load synthetic phishing URLs (realistic attack patterns)
synth_csv = os.path.join(os.path.dirname(__file__), "synthetic_phishing.csv")
if os.path.exists(synth_csv):
    df_synth = pd.read_csv(synth_csv)
    df_synth['source'] = 'synthetic'   # Tag for 5x weighting
    print(f"  Loaded {len(df_synth):,} synthetic phishing URLs")
    df = pd.concat([df, df_synth], ignore_index=True)

# Load Tranco top 50K safe URLs (250,000 URLs from top legitimate domains)
tranco_csv = os.path.join(os.path.dirname(__file__), "tranco_safe.csv")
if os.path.exists(tranco_csv):
    df_tranco = pd.read_csv(tranco_csv)
    print(f"  Loaded {len(df_tranco):,} Tranco safe URLs")
    df = pd.concat([df, df_tranco], ignore_index=True)
else:
    print("  No tranco_safe.csv found — place top-1m.csv in ml/ and run convert_tranco.py")

# Load Common Crawl safe URLs with deep paths (if available)
crawl_csv = os.path.join(os.path.dirname(__file__), "safe_deep_paths.csv")
if os.path.exists(crawl_csv):
    df_crawl = pd.read_csv(crawl_csv)
    print(f"  Loaded {len(df_crawl):,} Common Crawl safe URLs (deep paths)")
    df = pd.concat([df, df_crawl], ignore_index=True)

# Load safe SaaS subdomain URLs (teaches model that SaaS hosting is neutral context)
saas_csv = os.path.join(os.path.dirname(__file__), "safe_saas_urls.csv")
if os.path.exists(saas_csv):
    df_saas = pd.read_csv(saas_csv)
    print(f"  Loaded {len(df_saas):,} safe SaaS subdomain URLs")
    df = pd.concat([df, df_saas], ignore_index=True)
else:
    print("  No safe_saas_urls.csv found — place it in ml/ to improve SaaS URL detection")

df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
print(f"  Combined total (after deduplication): {len(df):,} URLs")
print()

# Show distribution of URL types
print("  Label distribution:")
for label, count in df["type"].value_counts().items():
    pct = count / len(df) * 100
    print(f"    {label:15s} {count:>7,}  ({pct:.1f}%)")
print()

# ── Step 2: Convert labels to binary ─────────────────────────────────────────

print("Step 2: Converting labels to binary (0=safe, 1=malicious)...")

# benign = 0 (safe)
# phishing, malware, defacement = 1 (malicious)
df['label'] = df['type'].apply(lambda t: 0 if t == 'benign' else 1)

safe_count      = (df['label'] == 0).sum()
malicious_count = (df['label'] == 1).sum()
print(f"  Safe URLs:      {safe_count:>7,}")
print(f"  Malicious URLs: {malicious_count:>7,}")
print()

# ── Optional: sample a subset for faster testing ──────────────────────────────

if SAMPLE_SIZE is not None:
    print(f"  Using sample of {SAMPLE_SIZE:,} URLs (SAMPLE_SIZE is set)")
    # Keep class balance when sampling
    df_safe      = df[df['label'] == 0].sample(SAMPLE_SIZE // 2, random_state=42)
    df_malicious = df[df['label'] == 1].sample(SAMPLE_SIZE // 2, random_state=42)
    df           = pd.concat([df_safe, df_malicious]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Sampled {len(df):,} URLs")
    print()

# ── Step 3: Extract 52 features for every URL ─────────────────────────────────

print(f"Step 3: Extracting 52 features for {len(df):,} URLs...")
print("  This is the most time-consuming step. Please wait...")
print()

start_time = time.time()
features_list = []
errors = 0

for i, row in enumerate(df.itertuples(), 1):
    try:
        features = extract_features(row.url)
        features_list.append(features)
    except Exception as e:
        # If a URL fails to parse, use zeros for all features
        errors += 1
        features_list.append({k: 0 for k in extract_features("http://example.com").keys()})

    # Show progress every 10,000 URLs
    if i % 10000 == 0:
        elapsed  = time.time() - start_time
        rate     = i / elapsed
        remaining = (len(df) - i) / rate
        print(f"  Processed {i:>7,} / {len(df):,} URLs "
              f"({i/len(df)*100:.1f}%) — "
              f"ETA: {remaining/60:.1f} min")

elapsed = time.time() - start_time
print()
print(f"  Feature extraction complete in {elapsed/60:.1f} minutes")
if errors > 0:
    print(f"  {errors} URLs failed to parse and were replaced with zeros")
print()

# ── Step 4: Build feature matrix ──────────────────────────────────────────────

print("Step 4: Building feature matrix...")

# Convert list of feature dicts to a DataFrame
features_df = pd.DataFrame(features_list)
feature_names = list(features_df.columns)

X = features_df.values          # Feature matrix (shape: n_urls × 52)
y = df['label'].values           # Labels (0 or 1)

print(f"  Feature matrix shape: {X.shape}")
print(f"  Number of features:   {X.shape[1]}")
print()

# ── Step 5: Split into training and test sets ─────────────────────────────────

print("Step 5: Splitting data (80% train, 20% test)...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y  # keeps class balance in both sets
)

print(f"  Training set: {len(X_train):,} URLs")
print(f"  Test set:     {len(X_test):,} URLs")
print()

# ── Step 6: Train XGBoost model ──────────────────────────────────────────────

print("Step 6: Training XGBoost model...")
print("  This takes 3-10 minutes. You will see progress below.")
print()

model = XGBClassifier(
    n_estimators=800,        # More trees — logloss was still declining at 500
    max_depth=7,             # Slightly deeper trees
    learning_rate=0.03,      # Lower learning rate — extracts more signal
    subsample=0.8,           # Use 80% of data for each tree (reduces overfitting)
    colsample_bytree=0.8,    # Use 80% of features for each tree
    min_child_weight=3,      # Prevents overfitting on rare patterns
    gamma=0.1,               # Minimum gain to make a split — reduces noise
    scale_pos_weight=safe_count / malicious_count,  # Handles class imbalance
    eval_metric='logloss',
    random_state=42,
    verbosity=1,
    n_jobs=-1,               # Use all CPU cores
)

# Build sample weights
# Priority order (highest to lowest):
#   4x — obvious killers (@ symbol, javascript:, null bytes etc.)
#   3x — classic phishing patterns (brand in subdomain, typosquatting etc.)
#   1x — normal Kaggle/synthetic URLs
#   0.5x — MongoDB plain domains (confuse model due to lack of path structure)
feature_names_list = list(features_df.columns)
classic_idx = feature_names_list.index('is_classic_phishing') if 'is_classic_phishing' in feature_names_list else None
killer_idx  = feature_names_list.index('obvious_killer_count') if 'obvious_killer_count' in feature_names_list else None

# Start with 1x for everything
sample_weights = np.ones(len(X_train))

# Get source column from original df aligned with training indices
# We need to track which training rows came from MongoDB
df_reset = df.reset_index(drop=True)
if 'source' in df_reset.columns:
    # Get the train indices from the split
    # X_train was split from X which came from features_df in df order
    # We rebuild the source array for the training set
    from sklearn.model_selection import train_test_split as tts
    _, _, _, _, source_train, _ = tts(
        features_df.values, df['label'].values, df_reset.get('source', pd.Series(['unknown']*len(df))).values,
        test_size=0.2, random_state=42, stratify=df['label'].values
    )
    # Give MongoDB plain domains 0.5x weight
    mongodb_mask = np.array([s == 'mongodb' for s in source_train])
    sample_weights[mongodb_mask] = 0.5
    print(f"  Sample weights: {mongodb_mask.sum():,} MongoDB URLs weighted 0.5x")

# Get synthetic phishing index — these cover exact attack patterns we target
synth_idx = feature_names_list.index('is_classic_phishing') if 'is_classic_phishing' in feature_names_list else None

if classic_idx is not None:
    # Classic phishing gets 3x (overrides 0.5x for mongodb phishing URLs)
    sample_weights[X_train[:, classic_idx] == 1] = 3.0
if killer_idx is not None:
    # Obvious killers get 4x
    sample_weights[X_train[:, killer_idx] > 0] = 4.0

# Synthetic phishing URLs get 5x weight — they were generated to specifically
# cover the attack patterns the model struggles with most
if 'source' in df_reset.columns:
    synth_mask = np.array([s == 'synthetic' for s in source_train])
    sample_weights[synth_mask & (X_train[:, classic_idx] == 1 if classic_idx else np.zeros(len(X_train), bool))] = 5.0
    print(f"  Sample weights: {synth_mask.sum():,} synthetic phishing URLs weighted 5x")

print(f"  Sample weights: {(sample_weights == 3.0).sum():,} classic phishing URLs weighted 3x")
print(f"  Sample weights: {(sample_weights == 4.0).sum():,} obvious killer URLs weighted 4x")
print()

train_start = time.time()
model.fit(
    X_train, y_train,
    sample_weight=sample_weights,
    eval_set=[(X_test, y_test)],
    verbose=50  # Print progress every 50 trees
)
train_time = time.time() - train_start

print()
print(f"  Training complete in {train_time/60:.1f} minutes")
print()

# ── Step 7: Quick evaluation on test set ─────────────────────────────────────

print("Step 7: Evaluating on test set...")

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"  Accuracy: {accuracy * 100:.2f}%")
print()
print("  Full report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))

# ── Step 8: Save the model ────────────────────────────────────────────────────

print("Step 8: Saving model...")

joblib.dump({
    'model':         model,
    'feature_names': feature_names,
    'accuracy':      accuracy,
}, MODEL_PATH)

print(f"  Model saved to: {MODEL_PATH}")
print()

# ── Step 9: Show top 10 most important features ───────────────────────────────

print("Step 9: Top 10 most important features (what the model learned):")

importances = model.feature_importances_
indices     = np.argsort(importances)[::-1]

for rank, idx in enumerate(indices[:10], 1):
    print(f"  {rank:2}. {feature_names[idx]:30s}  importance: {importances[idx]:.4f}")

print()
print("=" * 60)
print("Training complete! model.pkl is ready.")
print("Run evaluate.py for a detailed accuracy report.")
print("=" * 60)