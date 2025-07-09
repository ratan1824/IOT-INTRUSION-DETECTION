import os
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import accuracy_score

# -------------------- CONFIG --------------------
MODEL_PATH = "/Users/rohan/Desktop/ScienceFair/modelsxg/xgb_model.bin"
X_TEST_PATH = "/Users/rohan/Desktop/ScienceFair/data/processed/X_test_scaled.csv"
Y_TEST_PATH = "/Users/rohan/Desktop/ScienceFair/data/processed/y_test.csv"
# ------------------------------------------------

# ✅ Load the trained XGBoost model
print("📦 Loading XGBoost model...")
model = xgb.Booster()
model.load_model(MODEL_PATH)

# ✅ Load test data
print("📂 Loading test data...")
X_test = np.genfromtxt(X_TEST_PATH, delimiter=',')
y_test = pd.read_csv(Y_TEST_PATH).values.ravel()

# ✅ Predict on test data
print("🔍 Predicting...")
dtest = xgb.DMatrix(X_test)
y_pred = model.predict(dtest)

# ✅ Compute merror (classification error rate)
accuracy = accuracy_score(y_test, y_pred)
merror = 1 - accuracy

# ✅ Output results
print(f"\n✅ Test Accuracy: {accuracy:.6f}")
print(f"❌ Test merror  : {merror:.6f}")
