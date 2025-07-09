import os
import time
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
import xgboost as xgb
from xgboost.callback import TrainingCallback

# -------------------- CONFIG --------------------
PROCESSED_DIR = "/Users/rohan/Desktop/ScienceFair/data/processed/"
MODELS_DIR = "/Users/rohan/Desktop/ScienceFair/modelsxg2/"
os.makedirs(MODELS_DIR, exist_ok=True)

X_TRAIN_PATH = os.path.join(PROCESSED_DIR, 'X_train_scaled.csv')
X_TEST_PATH = os.path.join(PROCESSED_DIR, 'X_test_scaled.csv')
Y_TRAIN_PATH = os.path.join(PROCESSED_DIR, 'y_train.csv')
Y_TEST_PATH = os.path.join(PROCESSED_DIR, 'y_test.csv')
# ------------------------------------------------

# ✅ Load data
print("📂 Loading data...")
X_train = np.genfromtxt(X_TRAIN_PATH, delimiter=',')
X_test = np.genfromtxt(X_TEST_PATH, delimiter=',')
y_train = pd.read_csv(Y_TRAIN_PATH).values.ravel()
y_test = pd.read_csv(Y_TEST_PATH).values.ravel()

# ✅ Prepare DMatrix
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)

# ✅ Parameters
params = {
    'objective': 'multi:softmax',
    'num_class': 11,
    'max_depth': 6,
    'eta': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'eval_metric': ['merror', 'mlogloss']
}

num_rounds = 100
evals_result = {}

# ✅ TQDM progress bar callback
class TQDMProgressBar(TrainingCallback):
    def __init__(self, total_rounds):
        self.pbar = tqdm(total=total_rounds, desc="Training XGBoost", unit="round")

    def after_iteration(self, model, epoch, evals_log):
        self.pbar.update(1)
        return False

    def after_training(self, model):
        self.pbar.close()
        return model

# ✅ Train the model
print("🧠 Training XGBoost...")
start = time.process_time()
xgb_model = xgb.train(
    params=params,
    dtrain=dtrain,
    num_boost_round=num_rounds,
    evals=[(dtrain, 'train')],
    evals_result=evals_result,
    callbacks=[TQDMProgressBar(num_rounds)]
)
train_time = time.process_time() - start
print("✅ Training complete in", round(train_time, 2), "seconds")

# ✅ Save the model
model_path = os.path.join(MODELS_DIR, "xgb_model.bin")
xgb_model.save_model(model_path)
print(f"💾 Model saved to {model_path}")

# ✅ Save training metrics to JSON
evals_path = os.path.join(MODELS_DIR, "xgb_evals.json")
with open(evals_path, "w") as f:
    json.dump(evals_result, f, indent=4)
print(f"📊 Training metrics saved to {evals_path}")

# ✅ Plot Accuracy and Loss (Separate Graphs)
rounds = range(1, num_rounds + 1)
train_merror = evals_result['train']['merror']
train_accuracy = [1 - e for e in train_merror]
train_logloss = evals_result['train']['mlogloss']

# Plot Accuracy
plt.figure(figsize=(8, 5))
plt.plot(rounds, train_accuracy, marker='o', label='Train Accuracy', color='green')
plt.title("XGBoost Training Accuracy")
plt.xlabel("Boosting Round")
plt.ylabel("Accuracy")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()

# Plot Log Loss
plt.figure(figsize=(8, 5))
plt.plot(rounds, train_logloss, marker='o', label='Train Log Loss', color='red')
plt.title("XGBoost Training Log Loss")
plt.xlabel("Boosting Round")
plt.ylabel("Log Loss")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
