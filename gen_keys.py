# gen_keys.py
from pqcrypto.kem import ml_kem_512

print("Generating KEM keys...")
pk, sk = ml_kem_512.generate_keypair()

with open("receiver_pk.bin", "wb") as f:
    f.write(bytes(pk))
    
with open("receiver_sk.bin", "wb") as f:
    f.write(bytes(sk))

print("Keys saved: receiver_pk.bin, receiver_sk.bin")