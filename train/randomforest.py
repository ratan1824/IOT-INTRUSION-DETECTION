import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ✅ Import preprocessing function from your package
from src.features.build_features import preprocess

# -------------------- CONFIG --------------------
DATASET_PATH = "/Users/rohan/Desktop/ScienceFair/data/labelled/all_data_labelled.csv"
MODELS_DIR = "/Users/rohan/Desktop/ScienceFair/models/"
PROCESSED_DIR = "/Users/rohan/Desktop/ScienceFair/data/processed/"
os.makedirs(MODELS_DIR, exist_ok=True)
# ------------------------------------------------

# ✅ Step 1: Load and preprocess the dataset
print("📦 Preprocessing dataset...")
df = pd.read_csv(DATASET_PATH)
X_train_scaled, X_test_scaled, y_train, y_test = preprocess(
    data=df,
    train=True,
    save=True,
    path=PROCESSED_DIR
)

# ✅ Step 2: Train Random Forest
print("🧠 Training Random Forest model...")
n_estimators = 100
model = RandomForestClassifier(
    n_estimators=1,  # start with 1 and grow manually
    max_depth=10,
    warm_start=True,  # allow manual growth
    n_jobs=-1,
    random_state=42
)

train_start = time.process_time()
with tqdm(total=n_estimators, desc="Training Trees", unit=" tree") as pbar:
    for i in range(1, n_estimators + 1):
        model.set_params(n_estimators=i)
        model.fit(X_train_scaled, y_train)
        pbar.update(1)
train_time = time.process_time() - train_start

# ✅ Step 3: Save the trained model
model_path = os.path.join(MODELS_DIR, "rf_model.joblib")
joblib.dump(model, model_path)
print(f"💾 Model saved to {model_path}")

# ✅ Step 4: Evaluate the model
print("🧪 Evaluating model...")
inf_start = time.process_time()
preds = model.predict(X_test_scaled)
inf_time = time.process_time() - inf_start

# ✅ Step 5: Metrics
metrics = {
    "train_time": train_time,
    "inf_time/d_point": inf_time / len(preds),
}

report = classification_report(y_test, preds, output_dict=True)
for label, result in report.items():
    if isinstance(result, dict) and 'f1-score' in result:
        label_clean = f"F1 {label}" if 'avg' in label else f"class {label}"
        metrics[label_clean] = round(result['f1-score'], 3)

# ✅ Step 6: Save metrics
metrics_path = os.path.join(MODELS_DIR, "rf_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=4, sort_keys=True)

print(f"📊 Metrics saved to {metrics_path}")
print(json.dumps(metrics, indent=4))
