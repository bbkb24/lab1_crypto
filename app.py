from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import collections
import math
import hashlib
import jwt
import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_cyber_key'
DB_NAME = 'users.db'

JWT_SECRET = 'BozhenaBoiko'
MY_LIST_NUMBER = 2

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL)''')
    
    c.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", 
              (1, 'Антошків', hash_password('Роман')))
    c.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", 
              (2, 'Бойко', hash_password('Божена')))
    c.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", 
              (3, 'Бондарчук', hash_password('Ілья')))
              
    conn.commit()
    conn.close()

init_db()

# Алгоритми шифрування та криптоаналізу
def caesar_cipher(text, shift, decrypt=False):
    ukr_alphabet = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
    eng_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if decrypt: shift = -shift
    result = ""
    for char in text:
        if char.upper() in ukr_alphabet: alphabet = ukr_alphabet
        elif char.upper() in eng_alphabet: alphabet = eng_alphabet
        else:
            result += char
            continue
        is_lower = char.islower()
        idx = alphabet.find(char.upper())
        new_idx = (idx + shift) % len(alphabet)
        new_char = alphabet[new_idx]
        result += new_char.lower() if is_lower else new_char
    return result

def frequency_analysis(text):
    text = ''.join([c.upper() for c in text if c.isalpha()])
    if not text: return {}
    counter = collections.Counter(text)
    total = sum(counter.values())
    freq = {k: round((v / total) * 100, 2) for k, v in counter.items()}
    return dict(sorted(freq.items(), key=lambda item: item[1], reverse=True))

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
            for row in grid: result += row[k]
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

def horizontal_permutation(text, key, decrypt=False):
    text = text.replace(" ", "")
    key_order = [key.find(c) for c in sorted(key)]
    rows = len(key)
    cols = math.ceil(len(text) / rows)
    if not decrypt:
        padded_text = text.ljust(rows * cols, 'X')
        grid = [padded_text[i:i+cols] for i in range(0, len(padded_text), cols)]
        result = ""
        for k in key_order: result += grid[k]
        return result
    else:
        grid = [''] * rows
        row_len = cols
        idx = 0
        for k in key_order:
            grid[k] = text[idx:idx+row_len]
            idx += row_len
        return "".join(grid)

def combined_permutation(text, key1, key2, decrypt=False):
    if not decrypt:
        return vertical_permutation(horizontal_permutation(text, key1), key2)
    else:
        return horizontal_permutation(vertical_permutation(text, key2, decrypt=True), key1, decrypt=True)

# Маршрутизація та АРІ
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        is_api = request.is_json or 'Postman' in request.headers.get('User-Agent', '')
        
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if request.form.get('action') == 'register':
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()
                c.execute("SELECT MAX(id) FROM users")
                new_id = (c.fetchone()[0] or 0) + 1
                try:
                    c.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", 
                              (new_id, username, hash_password(password)))
                    conn.commit()
                    flash('Реєстрація успішна! Тепер увійдіть.', 'success')
                except sqlite3.IntegrityError:
                    flash('Користувач вже існує!', 'danger')
                conn.close()
                return render_template('login.html')

        hashed_pw = hash_password(password)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE username = ? AND password_hash = ?", (username, hashed_pw))
        user = c.fetchone()
        conn.close()
        
        if user:
            payload = {
                'login': user[1],
                'id': user[0],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=MY_LIST_NUMBER)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
            
            if is_api:
                return jsonify({
                    'message': 'Користувач був успішно авторизований',
                    'token': token
                }), 200
            else:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['jwt_token'] = token
                flash('Користувач був успішно авторизований', 'success')
                return redirect(url_for('index'))
        else:
            if is_api:
                return jsonify({'message': 'Невірний логін або пароль!'}), 401
            flash('Невірний логін або пароль!', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/protected', methods=['GET', 'POST'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Відсутній токен авторизації'}), 401
        
    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({
            'message': 'Успішний доступ до захищеного шляху!',
            'user_data': decoded
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Час дії токена минув'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Невалідний токен'}), 401

@app.route('/process', methods=['POST'])
def process():
    if 'user_id' not in session: return redirect(url_for('login'))
    text = request.form.get('text', '')
    cipher_type = request.form.get('cipher_type')
    action = request.form.get('action')
    result = ""; freq = None
    
    if cipher_type == 'caesar':
        shift = int(request.form.get('shift', 3))
        result = caesar_cipher(text, shift, decrypt=(action == 'decrypt'))
        if action == 'freq': freq = frequency_analysis(text)
    elif cipher_type == 'vertical':
        result = vertical_permutation(text, request.form.get('key', 'KEY'), decrypt=(action == 'decrypt'))
    elif cipher_type == 'horizontal':
        result = horizontal_permutation(text, request.form.get('key', 'KEY'), decrypt=(action == 'decrypt'))
    elif cipher_type == 'combined':
        result = combined_permutation(text, request.form.get('key', 'KEY1'), request.form.get('key2', 'KEY2'), decrypt=(action == 'decrypt'))
        
    return render_template('index.html', username=session.get('username'), original_text=text, result=result, freq=freq)

if __name__ == '__main__':
    app.run(debug=True)