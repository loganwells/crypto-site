from flask import jsonify
from crypto_utils.encryption import hash_file_sha
from crypto_utils.encryption import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa
from crypto_utils.encryption import encrypt_file_3des, decrypt_file_3des
from crypto_utils.encryption import encrypt_file_aes, decrypt_file_aes
from flask import send_file
from io import BytesIO
from crypto_utils.encryption import encrypt_file_aes
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mock user storage for now
users = {}

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users.values():
            if user.username == username and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in [u.username for u in users.values()]:
            flash('Username already exists.')
        else:
            user_id = str(len(users) + 1)
            password_hash = generate_password_hash(password)
            users[user_id] = User(user_id, username, password_hash)
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/encrypt_aes', methods=['POST'])
@login_required
def encrypt_aes():
    file = request.files['file']
    file_data = file.read()
    key_size = int(request.form['key_size'])
    mode = request.form['mode']

    encrypted = encrypt_file_aes(file_data, key_size, mode)

    return send_file(
        BytesIO(encrypted),
        download_name='encrypted_file.bin',
        as_attachment=True
    )

@app.route('/decrypt_aes', methods=['POST'])
@login_required
def decrypt_aes():
    file = request.files['file']
    encrypted_data = file.read()

    # For now, we assume CBC mode always
    decrypted_data = decrypt_file_aes(encrypted_data, mode='CBC')

    return send_file(
        BytesIO(decrypted_data),
        download_name='decrypted_output',
        as_attachment=True
    )

@app.route('/encrypt_3des', methods=['POST'])
@login_required
def encrypt_3des():
    file = request.files['file']
    file_data = file.read()
    encrypted = encrypt_file_3des(file_data)
    return send_file(BytesIO(encrypted), download_name='encrypted_3des.bin', as_attachment=True)

@app.route('/decrypt_3des', methods=['POST'])
@login_required
def decrypt_3des():
    file = request.files['file']
    file_data = file.read()
    decrypted = decrypt_file_3des(file_data)
    return send_file(BytesIO(decrypted), download_name='decrypted_3des_output', as_attachment=True)

@app.route('/generate_rsa_keys', methods=['POST'])
@login_required
def generate_rsa_keys_route():
    pub_key, priv_key = generate_rsa_keys()
    return send_file(BytesIO(pub_key + b'\n' + priv_key),
                     download_name='rsa_keys.pem',
                     as_attachment=True)

@app.route('/encrypt_rsa', methods=['POST'])
@login_required
def encrypt_rsa():
    pub_key = request.files['pub_key'].read()
    file_data = request.files['file'].read()
    encrypted = encrypt_file_rsa(file_data, pub_key)
    return send_file(BytesIO(encrypted), download_name='encrypted_rsa.bin', as_attachment=True)

@app.route('/decrypt_rsa', methods=['POST'])
@login_required
def decrypt_rsa():
    priv_key = request.files['priv_key'].read()
    encrypted = request.files['file'].read()
    decrypted = decrypt_file_rsa(encrypted, priv_key)
    return send_file(BytesIO(decrypted), download_name='decrypted_rsa_output', as_attachment=True)

@app.route('/hash_file', methods=['POST'])
@login_required
def hash_file():
    file = request.files['file']
    algo = request.form['algo']
    file_data = file.read()
    file_hash = hash_file_sha(file_data, algo)

    return f"<h2>{algo.upper()} Hash:</h2><p>{file_hash}</p><a href='/dashboard'>← Back</a>"


if __name__ == '__main__':
    app.run(debug=True)
