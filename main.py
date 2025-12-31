from DBManager import *
from pathlib import Path
from KeyGenerator import *
from rsa_encrypth import encrypt_file_rsa
db = Database()
generator = KeyGenerator(db)

user_id = "550e8400-e29b-41d4-a716-446655440000"
password = "password123"

# 1️⃣ Generate and store keys
key_id = generator.generate_and_store_keys(user_id, password)

if key_id:
    print(f"✅ Phase 2 Complete! Key ID: {key_id}")

    # 2️⃣ Encrypt file and save metadata
    input_path = input("Enter path to file to encrypt: ").strip()
    file_id = encrypt_file_rsa(db, user_id, key_id, input_path)
    if file_id:
        print(f"✅ File metadata inserted with ID: {file_id}")
else:
    print("❌ Phase 2 Failed")

db.close()
