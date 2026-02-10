import socket
import sys
from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- CONFIGURATION ---
# ML-KEM-512 Constants
KEM_CIPHERTEXT_LEN = 768  
AES_NONCE_LEN = 12
PORT = 5000

# 1. Load the Secret Key
try:
    with open("receiver_sk.bin", "rb") as f:
        sk_bytes = f.read()
    
    # Verify length to catch corruption early
    if len(sk_bytes) != 1632:
        raise ValueError(f"Corrupted Key! Expected 1632 bytes, got {len(sk_bytes)}")
        
    print("Loaded Secret Key from file.")
except FileNotFoundError:
    print("Error: receiver_sk.bin not found. Run gen_keys.py first!")
    sys.exit(1)

# 2. Network Setup
s = socket.socket()
# This line allows you to restart the script immediately without "Address already in use" errors
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('localhost', PORT))
s.listen(1)

print(f"Receiver listening on port {PORT}...")
print("Waiting for Sender...")

conn, addr = s.accept()
print(f"Connected to {addr}")

# Receive data (Simulating a single packet)
data = conn.recv(4096)
conn.close()

if not data:
    print("Error: Received empty data.")
    sys.exit(1)

# 3. PARSE DATA (Fixed Slicing)
# Structure: [KEM Ciphertext (768)] + [Nonce (12)] + [AES Ciphertext (Rest)]

# Slice 1: The KEM Ciphertext
ct_received = data[0 : KEM_CIPHERTEXT_LEN]

# Slice 2: The AES Nonce
nonce_received = data[KEM_CIPHERTEXT_LEN : KEM_CIPHERTEXT_LEN + AES_NONCE_LEN]

# Slice 3: The Actual Encrypted Message
ciphertext_received = data[KEM_CIPHERTEXT_LEN + AES_NONCE_LEN :]

print(f"Packet Parsed: CT={len(ct_received)}B, Nonce={len(nonce_received)}B, Msg={len(ciphertext_received)}B")

# 4. Decrypt KEM to get Shared Secret
try:
    # CRITICAL: Pass Secret Key (sk) FIRST, then Ciphertext (ct)
    ss_rec = ml_kem_512.decrypt(sk_bytes, ct_received)
    print("KEM Decapsulation successful.")
except Exception as e:
    print(f"KEM Failure: {e}")
    sys.exit(1)

# 5. Derive AES Key (Must match Sender's logic exactly)
hkdf_rec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'quantumpay',
)
symmetric_key_rec = hkdf_rec.derive(ss_rec)

# 6. Decrypt Transaction
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
    print("\n❌ AES Decryption Failed.")
    print("Possible causes: Wrong Public Key used by sender, or data corruption.")
    print(f"Error details: {e}")