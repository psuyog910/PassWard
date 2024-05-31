from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_oauthlib.client import OAuth
from cryptography.fernet import Fernet
import base64
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key='YOUR_GOOGLE_CLIENT_ID',
    consumer_secret='YOUR_GOOGLE_CLIENT_SECRET',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

def generate_key(passphrase):
    return base64.urlsafe_b64encode(passphrase.ljust(32)[:32].encode())

@app.route('/')
def index():
    if 'google_token' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/login/callback')
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    session['user'] = user_info.data
    return redirect(url_for('home'))

@app.route('/home')
def home():
    if 'google_token' not in session:
        return redirect(url_for('login'))
    user = session['user']
    return render_template_string('''
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <title>Password Manager</title>
        <style>
          body { background-color: #f7f9fc; }
          .container { margin-top: 50px; }
          .card { margin-bottom: 20px; }
          .btn-primary { background-color: #007bff; border-color: #007bff; }
          .result { margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="card">
            <div class="card-header">
              <h2>Password Encryption</h2>
            </div>
            <div class="card-body">
              <form id="encrypt-form">
                <div class="form-group">
                  <label for="password">Password to Encrypt:</label>
                  <input type="text" class="form-control" id="password" name="password" required>
                </div>
                <div class="form-group">
                  <label for="passkey">Passkey:</label>
                  <input type="text" class="form-control" id="passkey" name="passkey" required>
                </div>
                <button type="submit" class="btn btn-primary">Encrypt</button>
              </form>
              <div id="encrypt-result" class="result"></div>
            </div>
          </div>
          <div class="card">
            <div class="card-header">
              <h2>Password Decryption</h2>
            </div>
            <div class="card-body">
              <form id="decrypt-form">
                <div class="form-group">
                  <label for="encrypted_password">Encrypted Password:</label>
                  <input type="text" class="form-control" id="encrypted_password" name="encrypted_password" required>
                </div>
                <div class="form-group">
                  <label for="decrypt_passkey">Passkey:</label>
                  <input type="text" class="form-control" id="decrypt_passkey" name="passkey" required>
                </div>
                <button type="submit" class="btn btn-primary">Decrypt</button>
              </form>
              <div id="decrypt-result" class="result"></div>
            </div>
          </div>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script>
          $(document).ready(function() {
            $('#encrypt-form').on('submit', function(e) {
              e.preventDefault();
              $.ajax({
                type: 'POST',
                url: '/encrypt',
                data: $(this).serialize(),
                success: function(response) {
                  $('#encrypt-result').html('<div class="alert alert-success">Encrypted Password: ' + response.encrypted_password + '</div>');
                },
                error: function() {
                  $('#encrypt-result').html('<div class="alert alert-danger">An error occurred while encrypting the password.</div>');
                }
              });
            });
            $('#decrypt-form').on('submit', function(e) {
              e.preventDefault();
              $.ajax({
                type: 'POST',
                url: '/decrypt',
                data: $(this).serialize(),
                success: function(response) {
                  $('#decrypt-result').html('<div class="alert alert-success">Decrypted Password: ' + response.decrypted_password + '</div>');
                },
                error: function() {
                  $('#decrypt-result').html('<div class="alert alert-danger">An error occurred while decrypting the password.</div>');
                }
              });
            });
          });
        </script>
      </body>
    </html>
    ''')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    password = request.form['password']
    passkey = request.form['passkey']
    key = generate_key(passkey)
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode()).decode()
    return jsonify({"encrypted_password": encrypted_password})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_password = request.form['encrypted_password']
    passkey = request.form['passkey']
    key = generate_key(passkey)
    fernet = Fernet(key)
    try:
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
        return jsonify({"decrypted_password": decrypted_password})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
