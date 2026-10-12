from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import collections
import math

app = Flask(__name__)
app.secret_key = 'super_secret_cyber_key'
DB_NAME = 'users.db'

# --- Ініціалізація БД ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# --- Логіка шифрів ---
# 1. Шифр Цезаря
def caesar_cipher(text, shift, decrypt=False):
    ukr_alphabet = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
    eng_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if decrypt:
        shift = -shift
    
    result = ""
    for char in text:
        if char.upper() in ukr_alphabet:
            alphabet = ukr_alphabet
        elif char.upper() in eng_alphabet:
            alphabet = eng_alphabet
        else:
            result += char
            continue
            
        is_lower = char.islower()
        idx = alphabet.find(char.upper())
        new_idx = (idx + shift) % len(alphabet)
        new_char = alphabet[new_idx]
        result += new_char.lower() if is_lower else new_char
    return result

# 2. Частотний аналіз
def frequency_analysis(text):
    text = ''.join([c.upper() for c in text if c.isalpha()])
    if not text:
        return {}
    counter = collections.Counter(text)
    total = sum(counter.values())
    freq = {k: round((v / total) * 100, 2) for k, v in counter.items()}
    return dict(sorted(freq.items(), key=lambda item: item[1], reverse=True))

# 3. Вертикальна перестановка
def vertical_permutation(text, key, decrypt=False):
    text = text.replace(" ", "")
    key_order = [key.find(c) for c in sorted(key)]
    cols = len(key)
    
    if not decrypt:
        rows = math.ceil(len(text) / cols)
        padded_text = text.ljust(rows * cols, 'X')
        grid = [padded_text[i:i+cols] for i in range(0, len(padded_text), cols)]
        result = ""
        for k in key_order:
            for row in grid:
                result += row[k]
        return result
    else:
        rows = len(text) // cols
        grid = [[''] * cols for _ in range(rows)]
        idx = 0
        for k in key_order:
            for r in range(rows):
                grid[r][k] = text[idx]
                idx += 1
        return "".join(["".join(row) for row in grid])

# 4. Горизонтальна перестановка
def horizontal_permutation(text, key, decrypt=False):
    text = text.replace(" ", "")
    key_order = [key.find(c) for c in sorted(key)]
    rows = len(key)
    cols = math.ceil(len(text) / rows)
    
    if not decrypt:
        padded_text = text.ljust(rows * cols, 'X')
        grid = [padded_text[i:i+cols] for i in range(0, len(padded_text), cols)]
        result = ""
        for k in key_order:
            result += grid[k]
        return result
    else:
        grid = [''] * rows
        row_len = cols
        idx = 0
        for k in key_order:
            grid[k] = text[idx:idx+row_len]
            idx += row_len
        return "".join(grid)

# 5. Комбінована перестановка (подвійна)
def combined_permutation(text, key1, key2, decrypt=False):
    if not decrypt:
        step1 = horizontal_permutation(text, key1)
        step2 = vertical_permutation(step1, key2)
        return step2
    else:
        step1 = vertical_permutation(text, key2, decrypt=True)
        step2 = horizontal_permutation(step1, key1, decrypt=True)
        return step2

# --- Маршрути ---
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        if action == 'register':
            hashed_pw = generate_password_hash(password)
            try:
                c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                flash('Реєстрація успішна! Тепер увійдіть.', 'success')
            except sqlite3.IntegrityError:
                flash('Користувач вже існує!', 'danger')
        elif action == 'login':
            c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = username
                return redirect(url_for('index'))
            else:
                flash('Невірний логін або пароль!', 'danger')
        conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/process', methods=['POST'])
def process():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    text = request.form.get('text', '')
    cipher_type = request.form.get('cipher_type')
    action = request.form.get('action')
    
    result = ""
    freq = None
    
    if cipher_type == 'caesar':
        shift = int(request.form.get('shift', 3))
        result = caesar_cipher(text, shift, decrypt=(action == 'decrypt'))
        if action == 'freq':
            freq = frequency_analysis(text)
            
    elif cipher_type == 'vertical':
        key = request.form.get('key', 'KEY')
        result = vertical_permutation(text, key, decrypt=(action == 'decrypt'))
        
    elif cipher_type == 'horizontal':
        key = request.form.get('key', 'KEY')
        result = horizontal_permutation(text, key, decrypt=(action == 'decrypt'))
        
    elif cipher_type == 'combined':
        key1 = request.form.get('key', 'KEY1')
        key2 = request.form.get('key2', 'KEY2')
        result = combined_permutation(text, key1, key2, decrypt=(action == 'decrypt'))
        
    return render_template('index.html', username=session.get('username'), original_text=text, result=result, freq=freq)

if __name__ == '__main__':
    app.run(debug=True)