from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import os
import json

# --- Step 1: Load public key registry ---
with open("users.json", "r") as f:
    users = json.load(f)

# Choose the recipient
recipient = "Bob"  # Change as needed
if recipient not in users:
    print(f"Error: Recipient {recipient} not found in users.json")
    exit()

recipient_pk_file = users[recipient]

# --- Step 2: Load recipient's public key ---
try:
    with open(recipient_pk_file, "rb") as f:
        pk_bytes = f.read()
    print(f"Loaded {recipient}'s Public Key from {recipient_pk_file}.")
except FileNotFoundError:
    print(f"Error: {recipient_pk_file} not found! Generate keys first.")
    exit()

# --- Step 3: Encrypt KEM (encapsulate shared secret) ---
ct, ss_enc = ml_kem_512.encrypt(pk_bytes)

# --- Step 4: Derive AES key from shared secret ---
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'quantumpay',
)
symmetric_key = hkdf.derive(ss_enc)

# --- Step 5: Encrypt transaction using AES-GCM ---
transaction_data = b"Send 10 QuantumCoins to Bob"
aesgcm = AESGCM(symmetric_key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, transaction_data, associated_data=None)

# --- Step 6: Send over network ---
try:
    s = socket.socket()
    s.connect(('localhost', 5000))
    
    # Combine payload: KEM Ciphertext + Nonce + AES Ciphertext
    payload = ct + nonce + ciphertext
    s.sendall(payload)
    
    s.close()
    print(f"Transaction sent to {recipient}! Total bytes: {len(payload)}")
except ConnectionRefusedError:
    print("Error: Connection refused. Is receiver.py running?")
