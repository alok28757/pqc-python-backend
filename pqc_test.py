from pqcrypto.kem import ml_kem_512

# 1. Generate Keypair
# These are special internal objects, not just plain bytes
pk_obj, sk_obj = ml_kem_512.generate_keypair()

# 2. Encrypt
# We pass the public key OBJECT.
# It returns the ciphertext (ct) and the shared secret (ss_enc)
ct, ss_enc = ml_kem_512.encrypt(pk_obj)

# 3. Decrypt
# CRITICAL: Pass the 'sk_obj' directly. Do not convert to bytes.
ss_dec = ml_kem_512.decrypt(sk_obj, ct)

# 4. Verify
if ss_dec == ss_enc:
    print("Success! Shared secret matches.")
    print(f"Shared Secret: {ss_dec.hex()[:32]}...")
else:
    print("Error: Secrets do not match.")
