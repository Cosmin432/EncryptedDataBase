from DBManager import Database
from KeyGenerator import KeyGenerator
from rsa_encrypth import encrypt_file_hybrid
from rsa_decrypt import decrypt_file_hybrid
import getpass

db = Database()
generator = KeyGenerator(db)

user_id = "550e8400-e29b-41d4-a716-446655440000"
password = "password123"

# 1️⃣ Get active key
key_id = db.get_active_key_id(user_id)

if key_id:
    print(f"✅ Using existing key. Key ID: {key_id}")
else:
    # 2️⃣ Generate new key only if none exists
    key_id = generator.generate_and_store_keys(user_id, password)
    if not key_id:
        print("❌ Failed to generate keys. Exiting.")
        db.close()
        exit()
    print(f"✅ New key generated. Key ID: {key_id}")

# 3️⃣ Prompt user for action
action = input("Do you want to (E)ncrypt, (D)ecrypt or (X)Delete a file? [E/D/X]:").strip().upper()

if action == "E":
    input_path = input("Enter path to file to encrypt: ").strip()
    file_id = encrypt_file_hybrid(db, user_id, key_id, input_path)
    if file_id:
        print(f"✅ File encrypted and metadata stored. File ID: {file_id}")
    else:
        print("❌ Encryption failed.")

elif action == "D":
    file_id = input("Enter file ID to decrypt: ").strip()
    decrypt_password = input("Enter your password for decryption: ").strip()
    output_path = decrypt_file_hybrid(db, user_id, file_id, decrypt_password)
    if output_path:
        print(f"✅ File successfully decrypted: {output_path}")
    else:
        print("❌ Decryption failed. Check file ID, password, or file integrity.")
elif action == "X":
    file_id = input("Enter file ID to delete: ").strip()
    confirm = input("Type DELETE to confirm: ").strip()

    if confirm != "DELETE":
        print("❌ Deletion cancelled")
    else:
        from file_delete import delete_file
        delete_file(db, user_id, file_id)
else:
    print("❌ Invalid option. Please choose 'E' or 'D'.")

db.close()
