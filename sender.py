from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socket
import os
import time

# --- KEY LOADING STEP ---
# In a real app, load the Receiver's PK from a file/server.
# For this test to work, we must assume 'receiver_pk.bin' exists.
# If you don't have it, run a 'keygen.py' first!
try:
    with open("receiver_pk.bin", "rb") as f:
        pk_bytes = f.read()
    # Reconstruct the key object (library dependent, usually requires object or bytes)
    # Note: If your library version is strict, you might need the helper we discussed earlier.
    # For now, let's assume we can pass bytes to encrypt if the wrapper supports it,
    # or we need to reconstruct the object. 
    print("Loaded Receiver's Public Key.")
except FileNotFoundError:
    print("Error: receiver_pk.bin not found! Generate keys first.")
    exit()

# 1. Encrypt KEM (Encapsulate)
# Note: Check if your library version accepts raw bytes for 'encrypt'. 
# If not, you may need a helper to turn bytes back into a PK Object.
ct, ss_enc = ml_kem_512.encrypt(pk_bytes) 

# 2. Derive AES key
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'quantumpay',
)
symmetric_key = hkdf.derive(ss_enc)

# 3. Encrypt transaction
transaction_data = b"Send 10 QuantumCoins to Bob"
aesgcm = AESGCM(symmetric_key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, transaction_data, associated_data=None)

# 4. Send over network (Fixed Lengths, No Separators)
try:
    s = socket.socket()
    s.connect(('localhost', 5000))
    
    # Send combined payload: [KEM Ciphertext (768)] + [Nonce (12)] + [AES Ciphertext (Var)]
    payload = ct + nonce + ciphertext
    s.sendall(payload)
    
    s.close()
    print(f"Transaction sent! Total bytes: {len(payload)}")
except ConnectionRefusedError:
    print("Error: Connection refused. Is receiver.py running?")