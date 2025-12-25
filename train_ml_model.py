# Simple training script - You need labeled data (crypto functions vs normal)
# For demo, generate synthetic data

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
import joblib

# Synthetic crypto features: high bitwise
crypto_feats = [{'bitwise_ratio': 0.6 + np.random.rand()*0.2, 'arithmetic_ratio': 0.3, 'load_store_ratio': 0.1, 'unique_ops': 20, 'func_len': 200} for _ in range(100)]
normal_feats = [{'bitwise_ratio': 0.1, 'arithmetic_ratio': 0.2, 'load_store_ratio': 0.7, 'unique_ops': 30, 'func_len': 150} for _ in range(100)]

features = crypto_feats + normal_feats
labels = [1]*100 + [0]*100

vec = DictVectorizer()
X = vec.fit_transform(features)
model = RandomForestClassifier()
model.fit(X, labels)

joblib.dump((model, vec), 'model.pkl')
print("Model trained and saved.")