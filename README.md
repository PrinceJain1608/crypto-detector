# Crypto Primitive Detector

An advanced AI/ML-powered web tool for identifying cryptographic algorithms and primitives in multi-architecture firmware binaries.

## Features
- Rule-based detection of constants (AES S-box, SHA rounds, MD5, etc.)
- Machine Learning classification of crypto-like functions via disassembly
- Supports ARM, ARM64, MIPS32, x86_64
- Beautiful dark/light mode UI with history, exports (PDF/CSV), and more

## Live Demo
Coming soon!

## Setup
1. `pip install -r requirements.txt`
2. `python train_ml_model.py` (generates model.pkl)
3. `python app.py`

Built with Flask, Capstone, scikit-learn, Bootstrap.