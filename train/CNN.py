import os
import time
import json
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import classification_report
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, Input
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import Callback, ModelCheckpoint
from tensorflow.keras.optimizers import Adam

# -------------------- CONFIG --------------------
PROCESSED_DIR = "/Users/rohan/Desktop/ScienceFair/data/processed/"
MODELS_DIR = "/Users/rohan/Desktop/ScienceFair/modelscnn/"
os.makedirs(MODELS_DIR, exist_ok=True)
# ------------------------------------------------

# ✅ Step 1: Load preprocessed data
print("📂 Loading preprocessed data...")
X_train = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_train_scaled.csv'), delimiter=',')
X_test = np.genfromtxt(os.path.join(PROCESSED_DIR, 'X_test_scaled.csv'), delimiter=',')

y_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_train.csv')).values.ravel()
y_test = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_test.csv')).values.ravel()

# One-hot encode labels for CNN
num_classes = 11
y_train_cat = to_categorical(y_train, num_classes)
y_test_cat = to_categorical(y_test, num_classes)

# Reshape input to fit Conv1D: (samples, time steps, features)
X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
X_test = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))

# ✅ Step 2: Build CNN Model
input_shape = (X_train.shape[1], 1)
model = Sequential([
    Input(shape=input_shape),
    Conv1D(64, kernel_size=3, activation='relu'),
    MaxPooling1D(pool_size=2),
    Conv1D(128, kernel_size=3, activation='relu'),
    MaxPooling1D(pool_size=2),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.5),
    Dense(num_classes, activation='softmax')
])

model.compile(optimizer=Adam(learning_rate=0.001),
              loss='categorical_crossentropy',
              metrics=['accuracy'])

# ✅ Step 3: Progress Bar Callback
class TQDMProgressBar(Callback):
    def on_train_begin(self, logs=None):
        self.epochs = self.params['epochs']
        self.pbar = tqdm(total=self.epochs, desc='Training Epochs', unit='epoch')

    def on_epoch_end(self, epoch, logs=None):
        self.pbar.update(1)

    def on_train_end(self, logs=None):
        self.pbar.close()

# ✅ Step 4: Train CNN
print("🧠 Training CNN model...")
train_start = time.process_time()
model.fit(
    X_train, y_train_cat,
    epochs=20,
    batch_size=64,
    validation_data=(X_test, y_test_cat),
    callbacks=[TQDMProgressBar()],
    verbose=0
)
train_time = time.process_time() - train_start
print("✅ Training complete.")

# ✅ Step 5: Save Model
model_path = os.path.join(MODELS_DIR, "cnn_model.h5")
model.save(model_path)
print(f"💾 Model saved to {model_path}")

# ✅ Step 6: Evaluate
print("🧪 Evaluating model...")
inf_start = time.process_time()
y_pred_cat = model.predict(X_test)
y_pred = np.argmax(y_pred_cat, axis=1)
inf_time = time.process_time() - inf_start

metrics = {
    "train_time": train_time,
    "inf_time/d_point": inf_time / len(y_pred),
}

report = classification_report(y_test, y_pred, output_dict=True)
for label, result in report.items():
    if isinstance(result, dict) and 'f1-score' in result:
        label_clean = f"F1 {label}" if 'avg' in label else f"class {label}"
        metrics[label_clean] = round(result['f1-score'], 3)

# ✅ Step 7: Save metrics
metrics_path = os.path.join(MODELS_DIR, "cnn_metrics.json")
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=4, sort_keys=True)

print(f"📊 Metrics saved to {metrics_path}")
print(json.dumps(metrics, indent=4))
