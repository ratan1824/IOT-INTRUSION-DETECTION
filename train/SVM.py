import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.svm import SVC
from sklearn.metrics import classification_report

# -------------------- CONFIG --------------------
PROCESSED_DIR = "/Users/rohan/Desktop/ScienceFair/data/processed/"
MODELS_DIR = "/Users/rohan/Desktop/ScienceFair/models/"
os.makedirs(MODELS_DIR, exist_ok=True)
# ------------------------------------------------

# ✅ Step 1: Load preprocessed data
print("📂 Loading preprocessed data...")
X_train = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_train_scaled.csv'), delimiter=',')
X_test = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_test_scaled.csv'), delimiter=',')

y_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_train.csv')).values.ravel()
y_test = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_test.csv')).values.ravel()

# ✅ Step 2: Train SVM with progress bar
print("🧠 Training SVM model... (this may take time for large datasets)")

# Break training into batches to show progress
batch_size = X_train.shape[0] // 10
progress_bar = tqdm(total=X_train.shape[0], desc="Fitting SVM", unit="samples")

model = SVC(kernel='rbf', C=1.0, gamma='scale', probability=False)

start_time = time.process_time()
# Simulated progress bar (SVC does not support partial_fit or verbose progress)
model.fit(X_train, y_train)
progress_bar.update(X_train.shape[0])
progress_bar.close()
train_time = time.process_time() - start_time

print("✅ Training complete.")

# ✅ Step 3: Save model
model_path = os.path.join(MODELS_DIR, "svm_model.joblib")
joblib.dump(model, model_path)
print(f"💾 Model saved to {model_path}")

# ✅ Step 4: Evaluate model
print("🧪 Evaluating model...")
start_inf_time = time.process_time()
preds = model.predict(X_test)
inf_time = time.process_time() - start_inf_time

# ✅ Step 5: Save metrics
metrics = {
    "train_time": train_time,
    "inf_time/d_point": inf_time / len(preds),
}

report = classification_report(y_test, preds, output_dict=True)
for label, result in report.items():
    if isinstance(result, dict) and 'f1-score' in result:
        label_clean = f"F1 {label}" if 'avg' in label else f"class {label}"
        metrics[label_clean] = round(result['f1-score'], 3)

metrics_path = os.path.join(MODELS_DIR, "svm_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=4, sort_keys=True)

print(f"📊 Metrics saved to {metrics_path}")
print(json.dumps(metrics, indent=4))
