from pqcrypto.kem import ml_kem_512
import json

users = ["Alice", "Bob"]  # Add all usernames here
registry = {}

for username in users:
    print(f"Generating keys for {username}...")
    pk, sk = ml_kem_512.generate_keypair()
    
    pk_file = f"{username}_pk.bin"
    sk_file = f"{username}_sk.bin"
    
    with open(pk_file, "wb") as f: f.write(bytes(pk))
    with open(sk_file, "wb") as f: f.write(bytes(sk))
    
    registry[username] = pk_file
    print(f"{username} keys saved: {pk_file}, {sk_file}")

# Save the public key registry
with open("users.json", "w") as f:
    json.dump(registry, f, indent=4)

print("Public key registry saved as users.json")
