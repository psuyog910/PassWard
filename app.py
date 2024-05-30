import streamlit as st
import pyrebase
import streamlit_authenticator as stauth
from cryptography.fernet import Fernet
import base64
import hashlib
from google.cloud import firestore

# Firebase configuration using Streamlit secrets
firebase_config = {
    "apiKey": st.secrets["firebase"]["apiKey"],
    "authDomain": st.secrets["firebase"]["authDomain"],
    "projectId": st.secrets["firebase"]["projectId"],
    "storageBucket": st.secrets["firebase"]["storageBucket"],
    "messagingSenderId": st.secrets["firebase"]["messagingSenderId"],
    "appId": st.secrets["firebase"]["appId"],
    "measurementId": st.secrets["firebase"]["measurementId"]
}

# Initialize Firebase
firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()

# Initialize Firestore
db = firestore.Client()

# Generate a key based on the passkey
def get_key(passkey):
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

# Streamlit UI
st.title('SecurePass')

# User Authentication
authenticator = stauth.Authenticate(
    {'name': 'SecurePass', 'icon': '\\ud83d\\udd12'},
    'securepass'
)

name, authentication_status, username = authenticator.login('Login', 'main')

if authentication_status:
    st.success(f'Welcome {name}!')
    user_id = auth.current_user['localId']

    st.header('Encrypt a Password')
    with st.form('encrypt_form'):
        name = st.text_input('Password Name')
        password = st.text_input('Password', type='password')
        passkey = st.text_input('Passkey')
        encrypt_button = st.form_submit_button('Encrypt')

        if encrypt_button:
            encrypted_password = encrypt_password(password, passkey)
            db.collection("users").document(user_id).collection("passwords").add({
                "name": name,
                "encrypted_password": encrypted_password
            })
            st.success('Password encrypted and saved successfully!')

    st.header('Decrypt a Password')
    passwords = db.collection("users").document(user_id).collection("passwords").stream()
    password_list = {doc.id: doc.to_dict() for doc in passwords}
    if password_list:
        password_names = [pwd["name"] for pwd in password_list.values()]
        name = st.selectbox('Password Name', password_names)
        passkey = st.text_input('Passkey')
        decrypt_button = st.form_submit_button('Decrypt')

        if decrypt_button:
            for doc_id, pwd in password_list.items():
                if pwd["name"] == name:
                    encrypted_password = pwd["encrypted_password"]
                    try:
                        decrypted_password = decrypt_password(encrypted_password, passkey)
                        st.success(f'Decrypted Password: {decrypted_password}')
                    except Exception as e:
                        st.error('Invalid passkey or error decrypting password!')
                    break
    else:
        st.warning('No passwords found.')

elif authentication_status == False:
    st.error('Username/password is incorrect')

elif authentication_status == None:
    st.warning('Please enter your username and password')
