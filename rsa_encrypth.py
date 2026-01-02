from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import uuid
from file_reader import read_file_from_path
import os

def encrypt_file_hybrid(db, user_id: str, key_id: str, input_file_path: str) -> str:

    # 1️⃣ Get public key from DB
    public_key_pem = db.get_active_public_key(user_id)
    if not public_key_pem:
        print(f"❌ No active public key found for user {user_id}")
        return None

    # 2️⃣ Read the original file
    file_bytes = read_file_from_path(input_file_path)

    # 3️⃣ Generate random AES key
    aes_key = get_random_bytes(32)  # AES-256

    # 4️⃣ Encrypt file with AES (CBC mode)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_bytes)

    # 5️⃣ Encrypt AES key with RSA
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 6️⃣ Save hybrid encrypted file: [RSA_key_len][RSA_key][nonce_len][nonce][tag_len][tag][ciphertext]
    user_dir = Path("data/files") / user_id
    user_dir.mkdir(parents=True, exist_ok=True)

    file_id = str(uuid.uuid4())
    output_path = user_dir / f"{file_id}.enc"

    with open(output_path, "wb") as f:
        # store lengths to parse at decryption
        f.write(len(encrypted_aes_key).to_bytes(4, 'big'))
        f.write(encrypted_aes_key)
        f.write(len(cipher_aes.nonce).to_bytes(2, 'big'))
        f.write(cipher_aes.nonce)
        f.write(len(tag).to_bytes(2, 'big'))
        f.write(tag)
        f.write(ciphertext)

    print(f"✅ File encrypted and saved to: {output_path}")

    # 7️⃣ Insert metadata in DB
    inserted_file_id = db.insert_file_metadata(
        user_id=user_id,
        key_id=key_id,
        original_file_path=input_file_path,
        encrypted_file_path=str(output_path),
        shard_path=""  # optional
    )

    return inserted_file_id
