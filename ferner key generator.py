from cryptography.fernet import Fernet

# 1. Generate a new Fernet key
key = Fernet.generate_key()

# 2. Save it to a file (binary mode)
with open("fernet.key", "wb") as key_file:
    key_file.write(key)

print("Fernet key saved to fernet.key")