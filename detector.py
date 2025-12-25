import os
import yaml
import struct
from collections import Counter
import numpy as np
from capstone import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
import joblib

CONSTANTS_FILE = "constants.yaml"
MODEL_PATH = 'model.pkl'

with open(CONSTANTS_FILE, 'r') as f:
    CRYPTO_CONSTANTS = yaml.safe_load(f)

def search_constants_in_binary(binary_data):
    detections = {}
    for algo, tables in CRYPTO_CONSTANTS.items():
        for table_name, values in tables.items():
            for val in values:
                if isinstance(val, int):
                    packed_le = struct.pack("<I", val & 0xffffffff)
                    packed_be = struct.pack(">I", val & 0xffffffff)
                else:
                    packed_le = bytes(val)
                    packed_be = bytes(val[::-1])
                if packed_le in binary_data or packed_be in binary_data:
                    detections.setdefault(algo, []).append((table_name, hex(val) if isinstance(val, int) else str(val)))
    return detections

def disassemble_functions(binary_data, arch=CS_ARCH_ARM, mode=CS_MODE_ARM):
    md = Cs(arch, mode)
    md.detail = True
    functions = []
    current_func = []
    for insn in md.disasm(binary_data, 0x0):
        current_func.append(insn.mnemonic)
        if insn.mnemonic in ['ret', 'bx', 'pop', 'blr']:
            if len(current_func) > 10:
                functions.append(current_func)
            current_func = []
    return functions

def extract_features_from_functions(functions):
    features = []
    op_categories = {
        'bitwise': ['xor', 'and', 'or', 'not', 'shl', 'shr', 'rol', 'ror', 'bic'],
        'arithmetic': ['add', 'sub', 'mul', 'div', 'adc', 'sbc'],
        'load_store': ['ldr', 'str', 'ld', 'st', 'mov', 'push', 'pop'],
    }
    for func in functions:
        counts = Counter(func)
        total = sum(counts.values()) or 1
        feat = {
            'bitwise_ratio': sum(counts.get(op, 0) for op in op_categories['bitwise']) / total,
            'arithmetic_ratio': sum(counts.get(op, 0) for op in op_categories['arithmetic']) / total,
            'load_store_ratio': sum(counts.get(op, 0) for op in op_categories['load_store']) / total,
            'unique_ops': len(counts),
            'func_len': total,
        }
        features.append(feat)
    return features

def ml_classify_functions(features):
    if not os.path.exists(MODEL_PATH):
        return []
    model, vectorizer = joblib.load(MODEL_PATH)
    vec_features = vectorizer.transform(features)
    probs = model.predict_proba(vec_features)[:, 1]
    crypto_funcs = [(i, prob) for i, prob in enumerate(probs) if prob > 0.7]
    return crypto_funcs

def analyze_binary(binary_data, arch_mode):
    results = {}
    const_detections = search_constants_in_binary(binary_data)
    results['constants'] = const_detections

    arches_modes = {
        'x86_64': (CS_ARCH_X86, CS_MODE_64),
        'ARM': (CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN),
        'ARM64': (CS_ARCH_ARM64, CS_MODE_ARM),
        'MIPS32': (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
    }
    arch, mode = arches_modes.get(arch_mode, arches_modes['ARM'])
    
    try:
        functions = disassemble_functions(binary_data, arch, mode)
        if functions:
            features = extract_features_from_functions(functions)
            crypto_indices = ml_classify_functions(features)
            results['ml'] = {'functions': len(functions), 'crypto': crypto_indices, 'features': features}
        else:
            results['ml'] = {'error': 'No functions disassembled'}
    except Exception as e:
        results['ml'] = {'error': str(e)}
    
    return results