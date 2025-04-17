import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

KEY_FILE = "simple_secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())


def init_db():
    conn = sqlite3.connect("simple_secret.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
              label TEXT PRIMARY KEY,
              encrypted_text TEXT,
              password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def hash_passkey(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


st.title("Secure Data Encryption App")
menu = ["Store secret", "Retrieve secret"]
choice = st.sidebar.selectbox("Choose option", menu)

if choice == "Store secret":
    st.header("Store Secret")
    
    label = st.text_input("Label (unique ID): ")
    secret = st.text_area("Your Secret")
    password = st.text_input("Passkey", type="password")

    if st.button("Encrypt and Save"):
        if label and secret and password:
            conn = sqlite3.connect("simple_secret.db")
            c = conn.cursor()

            encrypted_secret = encrypt(secret)
            hashed_password = hash_passkey(password)
            try:
                c.execute("INSERT INTO vault (label, encrypted_text, password) VALUES (?, ?, ?)", (label, encrypted_secret, hashed_password))
                conn.commit()
                st.success("Secret stored successfully!")
            except sqlite3.IntegrityError:
                st.error("Label already exists. Please choose a different label.")
            conn.close()
        else:
            st.warning("Please fill in all fields.")

elif choice == "Retrieve secret":
    st.header("Retrieve Your Secret")

    label = st.text_input("Enter Label: ")
    password = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        conn = sqlite3.connect("simple_secret.db")
        c = conn.cursor()
        c.execute("SELECT encrypted_text, password FROM vault WHERE label=?", (label,))
        result = c.fetchone()
        conn.close()

        if result:
            encrypted_text, stored_hash = result
            if hash_passkey(password) == stored_hash:
                decrypted = decrypt(encrypted_text)
                st.success("Decrypted Secret:")
                st.code(decrypted)
            else:
                st.error("Incorrect passkey.")
        else:
            st.warning("No secret found with that label.")





      
       