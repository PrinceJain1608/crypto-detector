from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from werkzeug.utils import secure_filename
import os
import threading
import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import pandas as pd
from io import BytesIO
from detector import analyze_binary

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Change in production
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# SQLite DB for users and history
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, user_id INTEGER, file_name TEXT, arch TEXT, timestamp TEXT, results TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            session['user'] = username
            return redirect(url_for('analysis'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username exists')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = username
            return redirect(url_for('analysis'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/analysis', methods=['GET', 'POST'])
def analysis():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        files = request.files.getlist('files')
        arch = request.form['arch']
        results = []
        for file in files:
            if file:
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                with open(path, 'rb') as f:
                    data = f.read()
                result = analyze_binary(data, arch)
                results.append({'file': filename, 'result': result})
                # Save to history
                conn = sqlite3.connect('users.db')
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username=?", (session['user'],))
                user_id = c.fetchone()[0]
                c.execute("INSERT INTO history (user_id, file_name, arch, timestamp, results) VALUES (?, ?, ?, ?, ?)",
                          (user_id, filename, arch, datetime.now().isoformat(), str(result)))
                conn.commit()
                conn.close()
                os.remove(path)  # Clean up
        session['results'] = results
        return redirect(url_for('results'))
    return render_template('analysis.html')

@app.route('/results')
def results():
    if 'user' not in session or 'results' not in session:
        return redirect(url_for('analysis'))
    results = session.get('results', [])
    return render_template('results.html', results=results)

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (session['user'],))
    user_id = c.fetchone()[0]
    c.execute("SELECT * FROM history WHERE user_id=?", (user_id,))
    hist = c.fetchall()
    conn.close()
    return render_template('history.html', history=hist)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/export_pdf/<int:hist_id>')
def export_pdf(hist_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT results FROM history WHERE id=?", (hist_id,))
    results_str = c.fetchone()[0]
    conn.close()
    results = eval(results_str)  # Safe since we control input

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, "Crypto Detector Results")
    y = 700
    for key, val in results.items():
        c.drawString(100, y, f"{key}: {val}")
        y -= 20
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='results.pdf', mimetype='application/pdf')

@app.route('/export_csv/<int:hist_id>')
def export_csv(hist_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT results FROM history WHERE id=?", (hist_id,))
    results_str = c.fetchone()[0]
    conn.close()
    results = eval(results_str)

    df = pd.DataFrame([results])
    buffer = BytesIO()
    df.to_csv(buffer, index=False)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='results.csv', mimetype='text/csv')

@app.route('/progress')
def progress():
    # Placeholder for progress, can be enhanced with websockets
    return jsonify({'progress': 50})  # Dummy

if __name__ == '__main__':
    app.run(debug=True)