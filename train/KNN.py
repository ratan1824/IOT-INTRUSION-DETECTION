import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report

# -------------------- CONFIG --------------------
PROCESSED_DIR = "/Users/rohan/Desktop/ScienceFair/data/processed/"
MODELS_DIR = "/Users/rohan/Desktop/ScienceFair/modelsknn"
os.makedirs(MODELS_DIR, exist_ok=True)
# ------------------------------------------------

# ✅ Step 1: Load preprocessed data
print("📂 Loading preprocessed data...")
X_train = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_train_scaled.csv'), delimiter=',')
X_test = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_test_scaled.csv'), delimiter=',')

y_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_train.csv')).values.ravel()
y_test = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_test.csv')).values.ravel()

# ✅ Step 2: Train KNN (with simulated progress)
print("🧠 Training KNN model...")
k_neighbors = 5
progress = tqdm(total=1, desc="Training KNN", unit="step")

start_time = time.process_time()
model = KNeighborsClassifier(n_neighbors=k_neighbors, n_jobs=-1)
model.fit(X_train, y_train)
progress.update(1)
progress.close()
train_time = time.process_time() - start_time

print("✅ Training complete.")

# ✅ Step 3: Save model
model_path = os.path.join(MODELS_DIR, "knn_model.joblib")
joblib.dump(model, model_path)
print(f"💾 Model saved to {model_path}")

# ✅ Step 4: Evaluate
print("🧪 Evaluating model...")
start_inf = time.process_time()
preds = model.predict(X_test)
inf_time = time.process_time() - start_inf

metrics = {
    "train_time": train_time,
    "inf_time/d_point": inf_time / len(preds),
}

report = classification_report(y_test, preds, output_dict=True)
for label, result in report.items():
    if isinstance(result, dict) and 'f1-score' in result:
        label_clean = f"F1 {label}" if 'avg' in label else f"class {label}"
        metrics[label_clean] = round(result['f1-score'], 3)

# ✅ Step 5: Save metrics
metrics_path = os.path.join(MODELS_DIR, "knn_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=4, sort_keys=True)

print(f"📊 Metrics saved to {metrics_path}")
print(json.dumps(metrics, indent=4))
