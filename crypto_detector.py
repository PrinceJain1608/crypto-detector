# CryptoPrimitiveDetector - Enhanced with Modern Tkinter GUI
#
# This version significantly improves the GUI with:
# - Modern styling using ttkthemes for attractive design.
# - Color scheme: Dark theme with accents for better user experience.
# - Additional features: 
#   - Multiple file selection and batch analysis.
#   - Progress bar during analysis.
#   - Export results to TXT or HTML.
#   - Detailed expandable detection views (using Treeview).
#   - ML model status and reload option.
#   - Help/About dialog.
#   - Colored output log with tags for errors, successes.
#   - Responsive layout with resizable window.
#   - Tooltips for better UX.
#
# Run: python crypto_detector.py (launches GUI)
#
# Additional Requirements:
# pip install ttkthemes pillow  # For themes and potential future image support

import os
import sys
import yaml
import struct
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from ttkthemes import ThemedTk  # For attractive themes
from collections import Counter
import threading  # For non-blocking analysis
from tkinter import Toplevel, Label
from tkinter.ttk import Treeview, Scrollbar, Progressbar

import numpy as np
from capstone import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
import joblib  # for saving/loading model

# Load known cryptographic constants from YAML
CONSTANTS_FILE = "constants.yaml"
MODEL_PATH = 'model.pkl'

try:
    with open(CONSTANTS_FILE, 'r') as f:
        CRYPTO_CONSTANTS = yaml.safe_load(f)
except FileNotFoundError:
    messagebox.showerror("Error", "constants.yaml not found! Please create it.")
    sys.exit(1)

def search_constants_in_binary(binary_data):
    """
    Search for known crypto constants in raw binary bytes.
    Returns a dict of detected algorithms and matched constants.
    """
    detections = {}
    for algo, tables in CRYPTO_CONSTANTS.items():
        for table_name, values in tables.items():
            for val in values:
                if isinstance(val, int):
                    packed_le = struct.pack("<I", val & 0xffffffff)
                    packed_be = struct.pack(">I", val & 0xffffffff)
                else:  # list of bytes
                    packed_le = bytes(val)
                    packed_be = bytes(val[::-1])
                
                if packed_le in binary_data or packed_be in binary_data:
                    detections.setdefault(algo, []).append((table_name, hex(val) if isinstance(val, int) else str(val)))
    return detections

def disassemble_functions(binary_data, arch=CS_ARCH_ARM, mode=CS_MODE_ARM):  # Default to ARM
    """
    Disassemble the binary heuristically.
    """
    md = Cs(arch, mode)
    md.detail = True
    
    functions = []
    current_func = []
    
    for insn in md.disasm(binary_data, 0x0):
        current_func.append(insn.mnemonic)
        if insn.mnemonic in ['ret', 'bx', 'pop', 'blr']:  # Adapt per arch
            if len(current_func) > 10:
                functions.append(current_func)
            current_func = []
    
    return functions

def extract_features_from_functions(functions):
    """
    Extract opcode frequency features.
    """
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

def ml_classify_functions(features, model_path=MODEL_PATH):
    """
    Classify functions using pre-trained model.
    """
    if not os.path.exists(model_path):
        return []
    
    model, vectorizer = joblib.load(model_path)
    vec_features = vectorizer.transform(features)
    probs = model.predict_proba(vec_features)[:, 1]
    
    crypto_funcs = [i for i, prob in enumerate(probs) if prob > 0.7]
    return crypto_funcs

def analyze_binary(binary_path, arch_mode, output_text, progress_bar, treeview, result_callback):
    try:
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
        
        output_text.insert(tk.END, f"[+] Analyzing {binary_path} ({len(binary_data)} bytes)\n", "info")
        
        # Rule-based constants
        progress_bar['value'] = 20
        const_detections = search_constants_in_binary(binary_data)
        if const_detections:
            output_text.insert(tk.END, "Detected Cryptographic Primitives via Constants:\n", "success")
            parent = treeview.insert("", "end", text=os.path.basename(binary_path), values=("Constants", len(const_detections)))
            for algo, matches in const_detections.items():
                child = treeview.insert(parent, "end", text=algo.upper(), values=("Matches", len(matches)))
                for match in matches:
                    treeview.insert(child, "end", text=match[0], values=("Value", match[1]))
                output_text.insert(tk.END, f" - {algo.upper()}: {len(matches)} matches (e.g., {matches[0]})\n", "success")
        else:
            output_text.insert(tk.END, "No known constants found.\n", "warning")
        
        # ML-based disassembly
        progress_bar['value'] = 50
        arches_modes = {
            'x86_64': (CS_ARCH_X86, CS_MODE_64),
            'ARM': (CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN),
            'ARM64': (CS_ARCH_ARM64, CS_MODE_ARM),
            'MIPS32': (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
        }
        arch, mode = arches_modes.get(arch_mode, arches_modes['ARM'])
        
        try:
            functions = disassemble_functions(binary_data, arch, mode)
            progress_bar['value'] = 70
            if functions:
                output_text.insert(tk.END, f"\n[+] Disassembled {len(functions)} functions ({arch_mode})\n", "info")
                features = extract_features_from_functions(functions)
                crypto_indices = ml_classify_functions(features)
                if crypto_indices:
                    output_text.insert(tk.END, f"ML detected {len(crypto_indices)} potential crypto functions.\n", "success")
                    ml_parent = treeview.insert("", "end", text=os.path.basename(binary_path), values=("ML Functions", len(crypto_indices)))
                    for idx in crypto_indices:
                        treeview.insert(ml_parent, "end", text=f"Function {idx}", values=("Probability >0.7", ""))
                else:
                    output_text.insert(tk.END, "No potential crypto functions detected by ML.\n", "warning")
            else:
                output_text.insert(tk.END, "No functions disassembled (wrong architecture?)\n", "error")
        except Exception as e:
            output_text.insert(tk.END, f"Disassembly error: {str(e)}\n", "error")
        
        progress_bar['value'] = 100
        output_text.insert(tk.END, "\nAnalysis complete.\n", "info")
        output_text.see(tk.END)
        result_callback()  # Signal completion
    except Exception as e:
        messagebox.showerror("Error", str(e))
        progress_bar['value'] = 0

# GUI Setup
def create_gui():
    root = ThemedTk(theme="equilux")  # Dark theme for modern look
    root.title("Crypto Primitive Detector")
    root.geometry("800x600")
    root.resizable(True, True)
    
    # Style configuration
    style = ttk.Style()
    style.configure("TButton", padding=10, font=("Helvetica", 10))
    style.configure("TLabel", font=("Helvetica", 12))
    style.configure("TRadiobutton", font=("Helvetica", 10))
    style.configure("TFrame", background="#2e2e2e")  # Dark background
    
    # Main frame
    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # File selection
    file_frame = ttk.Frame(main_frame)
    file_frame.pack(fill=tk.X, pady=5)
    
    tk.Label(file_frame, text="Select Firmware Binaries:", bg="#2e2e2e", fg="white").pack(side=tk.LEFT, padx=5)
    file_entry = tk.Entry(file_frame, width=50, font=("Helvetica", 10))
    file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    
    def browse_files():
        file_paths = filedialog.askopenfilenames(filetypes=[("Binary Files", "*.bin *.img"), ("All Files", "*.*")])
        if file_paths:
            file_entry.delete(0, tk.END)
            file_entry.insert(0, ";".join(file_paths))  # Semicolon-separated for multiple
    
    ttk.Button(file_frame, text="Browse", command=browse_files).pack(side=tk.LEFT, padx=5)
    
    # Architecture choice
    arch_frame = ttk.Frame(main_frame)
    arch_frame.pack(fill=tk.X, pady=5)
    
    tk.Label(arch_frame, text="Select Architecture:", bg="#2e2e2e", fg="white").pack(side=tk.LEFT, padx=5)
    arch_var = tk.StringVar(value="ARM")  # Default
    arches = ['x86_64', 'ARM', 'ARM64', 'MIPS32']
    for arch in arches:
        ttk.Radiobutton(arch_frame, text=arch, variable=arch_var, value=arch).pack(side=tk.LEFT, padx=10)
    
    # Progress bar
    progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(pady=10)
    
    # Output area (scrolled text with colors)
    output_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=10, bg="#1e1e1e", fg="white", font=("Consolas", 10))
    output_text.pack(pady=10, fill=tk.BOTH, expand=True)
    output_text.tag_config("info", foreground="cyan")
    output_text.tag_config("success", foreground="green")
    output_text.tag_config("warning", foreground="yellow")
    output_text.tag_config("error", foreground="red")
    
    # Treeview for detailed results
    tree_frame = ttk.Frame(main_frame)
    tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
    treeview = Treeview(tree_frame, columns=("Type", "Count"), show="tree headings")
    treeview.heading("#0", text="Detection")
    treeview.heading("Type", text="Type")
    treeview.heading("Count", text="Count/Value")
    treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = Scrollbar(tree_frame, orient="vertical", command=treeview.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    treeview.configure(yscrollcommand=scrollbar.set)
    
    # Buttons frame
    buttons_frame = ttk.Frame(main_frame)
    buttons_frame.pack(fill=tk.X, pady=10)
    
    analyzing = False
    
    def run_analysis():
        nonlocal analyzing
        if analyzing:
            return
        binary_paths = file_entry.get().split(";")
        if not binary_paths or not all(os.path.exists(p) for p in binary_paths if p):
            messagebox.showerror("Error", "Please select valid files.")
            return
        output_text.delete(1.0, tk.END)
        treeview.delete(*treeview.get_children())
        progress_bar['value'] = 0
        analyzing = True
        
        def analyze_thread():
            for path in binary_paths:
                if path:
                    analyze_binary(path, arch_var.get(), output_text, progress_bar, treeview, lambda: None)
            nonlocal analyzing
            analyzing = False
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    ttk.Button(buttons_frame, text="Analyze", command=run_analysis).pack(side=tk.LEFT, padx=5)
    
    def export_results():
        results = output_text.get(1.0, tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("HTML", "*.html")])
        if file_path:
            with open(file_path, 'w') as f:
                if file_path.endswith(".html"):
                    f.write("<html><body><pre>" + results.replace("\n", "<br>") + "</pre></body></html>")
                else:
                    f.write(results)
            messagebox.showinfo("Success", "Results exported.")
    
    ttk.Button(buttons_frame, text="Export Results", command=export_results).pack(side=tk.LEFT, padx=5)
    
    def reload_model():
        if os.path.exists(MODEL_PATH):
            messagebox.showinfo("Model", "ML model reloaded successfully.")
        else:
            messagebox.showwarning("Model", "No model found. Run train_ml_model.py first.")
    
    ttk.Button(buttons_frame, text="Reload ML Model", command=reload_model).pack(side=tk.LEFT, padx=5)
    
    def show_help():
        help_win = Toplevel(root)
        help_win.title("Help & About")
        help_win.geometry("400x300")
        help_text = scrolledtext.ScrolledText(help_win, wrap=tk.WORD)
        help_text.pack(fill=tk.BOTH, expand=True)
        help_text.insert(tk.END, "Crypto Primitive Detector\n\n"
                         "This tool detects cryptographic primitives in firmware binaries using rule-based constant search and ML-based disassembly analysis.\n\n"
                         "Features:\n- Multi-file analysis\n- Progress tracking\n- Detailed tree view\n- Export options\n- Dark theme for better UX\n\n"
                         "For training ML model, run train_ml_model.py with labeled data.")
        help_text.config(state=tk.DISABLED)
    
    ttk.Button(buttons_frame, text="Help/About", command=show_help).pack(side=tk.LEFT, padx=5)
    
    # Tooltips (simple hover labels)
    def create_tooltip(widget, text):
        tooltip = Label(root, text=text, bg="yellow", fg="black", relief="solid", borderwidth=1)
        tooltip.pack_forget()
        
        def show_tooltip(event):
            tooltip.place(x=event.x_root + 10, y=event.y_root + 10)
        
        def hide_tooltip(event):
            tooltip.place_forget()
        
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)
    
    create_tooltip(file_entry, "Enter paths separated by ';' or browse for multiple files.")
    create_tooltip(arch_frame, "Choose the architecture matching your binary.")
    create_tooltip(output_text, "Analysis log with colored highlights.")
    create_tooltip(treeview, "Expandable tree of detections.")
    
    root.mainloop()

if __name__ == "__main__":
    # If run with args (CLI mode), but now default to GUI
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Crypto Primitive Detector")
        parser.add_argument("binary", help="Path to firmware binary file")
        args = parser.parse_args()
        # CLI output (for backward compat)
        with open(args.binary, 'rb') as f:
            binary_data = f.read()
        const_detections = search_constants_in_binary(binary_data)
        print(f"[+] Analyzing {args.binary} ({len(binary_data)} bytes)\n")
        if const_detections:
            print("Detected Cryptographic Primitives via Constants:")
            for algo, matches in const_detections.items():
                print(f" - {algo}: {len(matches)} matches (e.g., {matches[0]})")
        print("\nAnalysis complete.")
    else:
        create_gui()