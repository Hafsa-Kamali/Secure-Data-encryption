import streamlit as st
import hashlib
import json
import os
import sqlite3
from cryptography.fernet import Fernet

# ---------- File Constants ----------
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
LOGO_PATH = "logo.png"
# Add background image path
BG_IMAGE = "image3.jpg"  # Make sure this file exists in your directory

# ---------- Key Management ----------
def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

KEY = load_key()
cipher = Fernet(KEY)

# ---------- Data Handling ----------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

stored_data = load_data()

# ---------- SQLite Setup ----------
conn = sqlite3.connect("users.db")
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)''')
conn.commit()

# ---------- Helper Functions ----------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, username):
    hashed = hash_passkey(passkey)
    user_data = stored_data.get(username, {})

    if encrypted_text in user_data and user_data[encrypted_text]["passkey"] == hashed:
        return cipher.decrypt(encrypted_text.encode()).decode()
    return None

def user_exists(username):
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    return c.fetchone() is not None

def authenticate_user(username, password):
    hashed = hash_passkey(password)
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed))
    return c.fetchone()

def register_user(username, password):
    if not user_exists(username):
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_passkey(password)))
        conn.commit()
        return True
    return False

# ---------- Session State Initialization ----------
st.set_page_config(page_title="🔐 IronSafe Systems", layout="centered")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

if "theme" not in st.session_state:
    st.session_state.theme = "light"

# ---------- Background Image ----------
def set_background():
    # Check if background image exists
    if os.path.exists(BG_IMAGE):
        # Set background image with CSS
        bg_img = f"""
        <style>
        .stApp {{
            background-image: 
            url("data:image/jpg;base64,{get_base64_encoded_image(BG_IMAGE)}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }}
        </style>
        """
        st.markdown(bg_img, unsafe_allow_html=True)

def get_base64_encoded_image(image_path):
    """Get base64 encoded image to use in CSS"""
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode('utf-8')

# Load required module for base64 encoding
import base64

# Apply background
set_background()

# ---------- Theme Colors ----------
def set_theme():
    if st.session_state.theme == "dark":
        st.markdown("""
            <style>
            body { background-color: #0e1117; color: #fafafa; }
            .stButton>button { background-color: #444; color: white; }
            /* Apply semi-transparent overlay for better text readability over background */
            .stApp::before {
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(14, 17, 23, 0.7);  /* Dark theme overlay */
                z-index: -1;
            }
            </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <style>
            body { background-color: #ffffff; color: #222; }
            .stButton>button { background-color: #ddd; color: #000; }
            /* Apply semi-transparent overlay for better text readability over background */
            .stApp::before {
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(255, 255, 255, 0.7);  /* Light theme overlay */
                z-index: -1;
            }
            </style>
        """, unsafe_allow_html=True)

set_theme()

# ---------- Branding ----------
col1, col2 = st.columns([1, 4])
with col1:
    st.image(LOGO_PATH, width=70)
with col2:
    st.markdown("<h1 style='margin-top: 0;'>Secure Data Vault</h1>", unsafe_allow_html=True)

# ---------- Theme Switcher ---------- (move theme selection up)
theme = st.sidebar.radio("🎨 Theme", ["🌞 Light", "🌙 Dark"])
st.session_state.theme = "light" if theme == "🌞 Light" else "dark"

# NOW apply the theme after updating state
set_theme()

# ---------- Authentication ----------
if not st.session_state.logged_in:
    st.sidebar.markdown("## 🔐 Login/Register")
    auth_mode = st.sidebar.radio("Select Action:", ["Login", "Register"])

    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if auth_mode == "Login":
        if st.sidebar.button("Login"):
            if authenticate_user(username, password):
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.toast("✅ Logged in successfully!")
            else:
                st.sidebar.error("Invalid credentials.")
    else:
        if st.sidebar.button("Register"):
            if register_user(username, password):
                st.sidebar.success("Account created! You can now log in.")
            else:
                st.sidebar.error("Username already exists.")

else:
    st.sidebar.success(f"👋 Welcome, {st.session_state.current_user}")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.current_user = ""

    # ---------- App Navigation ----------
    menu = ["📂 Store Data", "🔍 Retrieve Data"]
    choice = st.sidebar.radio("📌 Navigate", menu)

    if choice == "📂 Store Data":
        st.header("📦 Store Data")

        data = st.text_area("🔒 Enter data to encrypt:")
        passkey = st.text_input("🔑 Set a passkey:", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_data(data)
                hashed = hash_passkey(passkey)

                username = st.session_state.current_user
                if username not in stored_data:
                    stored_data[username] = {}

                stored_data[username][encrypted] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
                st.code(encrypted)
            else:
                st.error("⚠️ Please provide both data and a passkey.")

    elif choice == "🔍 Retrieve Data":
        st.header("🔎 Retrieve Data")

        username = st.session_state.current_user
        passkey = st.text_input("🔑 Enter your passkey:", type="password")

        if username in stored_data:
            encrypted_items = list(stored_data[username].keys())
            if encrypted_items:
                encrypted_selected = st.selectbox("🧾 Select Encrypted Data:", encrypted_items)

                if st.button("Decrypt"):
                    result = decrypt_data(encrypted_selected, passkey, username)
                    if result:
                        st.success("✅ Decrypted Data:")
                        st.code(result)
                    else:
                        st.error("❌ Incorrect passkey.")
            else:
                st.warning("📭 No data found for your account.")