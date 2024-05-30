import streamlit as st
import sqlite3
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# Generate a key based on the passkey
def get_key(passkey):
    # Use SHA-256 to hash the passkey and then base64 encode the first 32 bytes
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

# Encrypt the password
def encrypt_password(password, passkey):
    fernet = Fernet(get_key(passkey))
    encrypted_password = fernet.encrypt(password.encode()).decode()
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password, passkey):
    fernet = Fernet(get_key(passkey))
    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
    return decrypted_password

# Initialize the database for the session
def init_db():
    if 'db_initialized' not in st.session_state:
        db_path = f"passwords_{st.session_state.session_id}.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                          (id INTEGER PRIMARY KEY, name TEXT, encrypted_password TEXT)''')
        conn.commit()
        conn.close()
        st.session_state['db_initialized'] = True
        st.session_state['db_path'] = db_path

# Streamlit UI
st.title('PassWard: Lock. Encrypt. Protect.')

# Initialize the database
if 'session_id' not in st.session_state:
    st.session_state['session_id'] = os.urandom(16).hex()
init_db()

st.header('Encrypt a Password')
with st.form('encrypt_form'):
    name = st.text_input('Password Name')
    password = st.text_input('Password', type='password')
    passkey = st.text_input('Passkey')
    encrypt_button = st.form_submit_button('Encrypt')

    if encrypt_button:
        encrypted_password = encrypt_password(password, passkey)

        conn = sqlite3.connect(st.session_state['db_path'])
        cursor = conn.cursor()
        cursor.execute('INSERT INTO passwords (name, encrypted_password) VALUES (?, ?)', (name, encrypted_password))
        conn.commit()
        conn.close()

        st.success('Password encrypted and saved successfully!')

st.header('Decrypt a Password')
with st.form('decrypt_form'):
    conn = sqlite3.connect(st.session_state['db_path'])
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM passwords')
    names = cursor.fetchall()
    conn.close()

    name = st.selectbox('Password Name', [name[0] for name in names])
    passkey = st.text_input('Passkey')
    decrypt_button = st.form_submit_button('Decrypt')

    if decrypt_button:
        conn = sqlite3.connect(st.session_state['db_path'])
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_password FROM passwords WHERE name=?', (name,))
        row = cursor.fetchone()
        conn.close()

        if row:
            encrypted_password = row[0]
            try:
                decrypted_password = decrypt_password(encrypted_password, passkey)
                st.success(f'Decrypted Password: {decrypted_password}')
            except Exception as e:
                st.error('Invalid passkey or error decrypting password!')
        else:
            st.error('No password found for the given name!')
