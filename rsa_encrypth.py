from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import uuid
from file_reader import read_file_from_path
from key_fs_manager import PRIVATE_KEYS_DIR, save_public_key
import os

def encrypt_file_rsa(db, user_id: str, key_id: str, input_file_path: str) -> str:
    """
    Encrypt a file with RSA public key from DB, save to disk, and insert metadata in DB.
    Returns: file_id if successful, None otherwise
    """

    # 1️⃣ Get public key from DB
    public_key_pem = db.get_active_public_key(user_id)
    if not public_key_pem:
        print(f"❌ No active public key found for user {user_id}")
        return None

    # 2️⃣ Read the original file
    file_bytes = read_file_from_path(input_file_path)

    # 3️⃣ Load public key
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # 4️⃣ Encrypt the file
    try:
        encrypted_bytes = cipher_rsa.encrypt(file_bytes)
    except ValueError as e:
        print(f"❌ ERROR: {e} (file too large for RSA direct encryption)")
        return None

    # 5️⃣ Prepare user folder
    user_dir = Path("data/files") / user_id
    user_dir.mkdir(parents=True, exist_ok=True)

    # 6️⃣ Generate file_id and output path
    file_id = str(uuid.uuid4())
    output_path = user_dir / f"{file_id}.enc"

    # 7️⃣ Save encrypted file
    with open(output_path, "wb") as f:
        f.write(encrypted_bytes)

    print(f"✅ File encrypted and saved to: {output_path}")

    # 8️⃣ Insert metadata in DB
    inserted_file_id = db.insert_file_metadata(
        user_id=user_id,
        key_id=key_id,
        original_file_path=input_file_path,
        encrypted_file_path=str(output_path),
         shard_path =""
    )

    return inserted_file_id
