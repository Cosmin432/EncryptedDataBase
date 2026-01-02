def encrypt_file_hybrid(db, user_id: str, key_id: str, input_file_path: str) -> str | None:
    """
    Encrypt a file using a hybrid AES+RSA scheme and store its metadata in the database.

    Steps:
        1. Retrieve the user's active public key from the database.
        2. Read the file content from disk.
        3. Generate a random AES-256 key.
        4. Encrypt the file using AES in EAX mode.
        5. Encrypt the AES key using the user's RSA public key.
        6. Save the encrypted data to a temporary file.
        7. Insert file metadata into the database (gets the official file_id).
        8. Rename the temporary file to match the database file_id and update the DB path.

    Args:
        db: Database instance for storing metadata and fetching public keys.
        user_id: UUID of the user performing the encryption.
        key_id: UUID of the encryption key to associate with the file.
        input_file_path: Path to the original file to encrypt.

    Returns:
        str: The UUID of the inserted file in the database if successful.
        None: If encryption or metadata insertion fails.

    Notes:
        - The function ensures that the encrypted file on disk matches the database file_id.
        - Temporary files are cleaned up if metadata insertion fails.
        - Prints detailed progress and error messages for debugging.
    """
    from pathlib import Path
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    import uuid
    import os
    from file_reader import read_file_from_path

    # 1️⃣ Get public key from DB
    public_key_pem = db.get_active_public_key(user_id)
    if not public_key_pem:
        print(f"❌ No active public key found for user {user_id}")
        return None

    # 2️⃣ Read the original file
    file_bytes = read_file_from_path(input_file_path)

    # 3️⃣ Generate random AES key
    aes_key = get_random_bytes(32)  # AES-256

    # 4️⃣ Encrypt file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_bytes)

    # 5️⃣ Encrypt AES key with RSA
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 6️⃣ Save to a temporary file first
    user_dir = Path("data/files") / user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    temp_file_name = str(uuid.uuid4()) + ".tmp"
    temp_file_path = user_dir / temp_file_name

    with open(temp_file_path, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(4, 'big'))
        f.write(encrypted_aes_key)
        f.write(len(cipher_aes.nonce).to_bytes(2, 'big'))
        f.write(cipher_aes.nonce)
        f.write(len(tag).to_bytes(2, 'big'))
        f.write(tag)
        f.write(ciphertext)

    # 7️⃣ Insert metadata in DB (returns the official file_id)
    inserted_file_id = db.insert_file_metadata(
        user_id=user_id,
        key_id=key_id,
        original_file_path=input_file_path,
        encrypted_file_path=str(temp_file_path),
        shard_path=""
    )

    if not inserted_file_id:
        print("❌ Failed to insert metadata. Cleaning up temp file.")
        temp_file_path.unlink(missing_ok=True)
        return None

    # 8️⃣ Rename temp file to match DB file_id
    final_file_path = user_dir / f"{inserted_file_id}.enc"
    temp_file_path.rename(final_file_path)

    db.update_file_path(inserted_file_id, str(final_file_path))
    print(f"✅ File encrypted and saved to: {final_file_path}")
    return inserted_file_id
