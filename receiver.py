import socket
import sys
from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json

# --- CONFIGURATION ---
KEM_CIPHERTEXT_LEN = 768  
AES_NONCE_LEN = 12
PORT = 5000

# --- Step 1: Choose your username ---
# This receiver’s username must match the one in users.json
username = "Bob"  # Change this if another user is running receiver.py

# --- Step 2: Load Secret Key ---
sk_file = f"{username}_sk.bin"
try:
    with open(sk_file, "rb") as f:
        sk_bytes = f.read()
    
    if len(sk_bytes) != 1632:
        raise ValueError(f"Corrupted Key! Expected 1632 bytes, got {len(sk_bytes)}")
    
    print(f"Loaded Secret Key for {username} from {sk_file}.")
except FileNotFoundError:
    print(f"Error: {sk_file} not found. Run gen_keys.py first!")
    sys.exit(1)

# --- Step 3: Setup Network ---
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('localhost', PORT))
s.listen(1)

print(f"{username} listening on port {PORT}...")
print("Waiting for Sender...")

conn, addr = s.accept()
print(f"Connected to {addr}")

# Receive data
data = conn.recv(4096)
conn.close()

if not data:
    print("Error: Received empty data.")
    sys.exit(1)

# --- Step 4: Parse Payload ---
ct_received = data[0 : KEM_CIPHERTEXT_LEN]
nonce_received = data[KEM_CIPHERTEXT_LEN : KEM_CIPHERTEXT_LEN + AES_NONCE_LEN]
ciphertext_received = data[KEM_CIPHERTEXT_LEN + AES_NONCE_LEN :]

print(f"Packet Parsed: CT={len(ct_received)}B, Nonce={len(nonce_received)}B, Msg={len(ciphertext_received)}B")

# --- Step 5: Decrypt KEM to get shared secret ---
try:
    ss_rec = ml_kem_512.decrypt(sk_bytes, ct_received)
    print("KEM Decapsulation successful.")
except Exception as e:
    print(f"KEM Failure: {e}")
    sys.exit(1)

# --- Step 6: Derive AES Key ---
hkdf_rec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'quantumpay',
)
symmetric_key_rec = hkdf_rec.derive(ss_rec)

# --- Step 7: Decrypt AES-GCM transaction ---
try:
    aesgcm_rec = AESGCM(symmetric_key_rec)
    transaction_decrypted = aesgcm_rec.decrypt(
        nonce_received,
        ciphertext_received,
        associated_data=None
    )
    print("\n✅ SUCCESS!")
    print(f"Decrypted Message: {transaction_decrypted.decode()}")
except Exception as e:
    print("\n AES Decryption Failed.")
    print("Possible causes: Wrong Public Key used by sender, or data corruption.")
    print(f"Error details: {e}")
