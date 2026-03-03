import numpy as np
import tensorflow as tf
import joblib
import os
import pandas as pd
from config import (
    MODEL_DIR,
    ATTACK_SEVERITY_MAP,
    MOCK_CLASS_NAMES,
    MOCK_CLASS_WEIGHTS,
    MOCK_CONFIDENCE_MIN,
    MOCK_CONFIDENCE_MAX,
    MOCK_MODEL_METRICS_UNLOADED,
    MOCK_MODEL_METRICS_LOADED,
)


class NIDSPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.feature_columns = None
        self.loaded = False

    def load(self):
        path = os.path.join(MODEL_DIR, "nids_cnn_model.keras")
        if not os.path.exists(path):
            path = os.path.join(MODEL_DIR, "best_model.keras")
        if not os.path.exists(path):
            self.loaded = True
            return
        self.model = tf.keras.models.load_model(path)
        self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        self.label_encoders = joblib.load(os.path.join(MODEL_DIR, "label_encoders.pkl"))
        self.feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
        self.loaded = True

    def predict(self, features_dict):
        if not self.loaded:
            self.load()
        if self.model is None:
            # Mock prediction when no model is available
            import random
            types = MOCK_CLASS_NAMES
            weights = MOCK_CLASS_WEIGHTS
            class_name = random.choices(types, weights=weights)[0]
            confidence = MOCK_CONFIDENCE_MIN + random.random() * max(0.0, MOCK_CONFIDENCE_MAX - MOCK_CONFIDENCE_MIN)
            probabilities = {t: weights[i] for i, t in enumerate(types)}
            return {
                "prediction": class_name,
                "confidence": confidence,
                "severity": ATTACK_SEVERITY_MAP.get(class_name, "unknown"),
                "probabilities": probabilities,
                "is_malicious": class_name != "normal"
            }
        df = pd.DataFrame([features_dict])
        for col, le in self.label_encoders.items():
            if col in df.columns and col != "category":
                try:
                    df[col] = le.transform(df[col].astype(str))
                except ValueError:
                    df[col] = 0
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        X = df[self.feature_columns].values.astype(np.float32)
        X = self.scaler.transform(X)
        X = X.reshape(X.shape[0], X.shape[1], 1)

        proba = self.model.predict(X, verbose=0)[0]
        pred_idx = int(np.argmax(proba))
        le = self.label_encoders["category"]
        class_name = le.inverse_transform([pred_idx])[0]

        return {
            "prediction": class_name,
            "confidence": float(np.max(proba)),
            "severity": ATTACK_SEVERITY_MAP.get(class_name, "unknown"),
            "probabilities": {le.inverse_transform([i])[0]: float(p) for i, p in enumerate(proba)},
            "is_malicious": class_name != "normal"
        }

    def get_model_info(self):
        if not self.loaded:
            self.load()
        if self.model is None:
            return {
                "model_loaded": False,
                "metrics": MOCK_MODEL_METRICS_UNLOADED
            }
        return {
            "model_loaded": True,
            "metrics": MOCK_MODEL_METRICS_LOADED
        }
