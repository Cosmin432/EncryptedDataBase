from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from DBManager import Database
from KeyGenerator import KeyGenerator
import getpass

def decrypt_file_hybrid(db: Database, user_id: str, file_id: str, password: str, output_dir="data/decrypted") -> Path:
    """
    Decrypt file encrypted with hybrid RSA + AES with verbose debug messages
    """
    print(f"\n🔍 Starting decryption for file ID: {file_id} and user: {user_id}")

    # 1️⃣ Fetch decryption info from DB
    info = db.get_file_decryption_info(user_id, file_id)
    if not info:
        print("❌ Failed to fetch decryption info from DB")
        return None
    print(f"✅ Fetched decryption info from DB: {info}")

    encrypted_file_path = info["encrypted_file_path"]
    encrypted_private_key = info["encrypted_private_key"]
    salt = info["salt"]

    # 2️⃣ Decrypt private key
    try:
        print("🔓 Decrypting private key...")
        private_key_pem = KeyGenerator.decrypt_private_key(encrypted_private_key, password, salt)
        private_key = RSA.import_key(private_key_pem)
        print(f"✅ Private key decrypted successfully")
    except Exception as e:
        print(f"❌ Failed to decrypt private key: {e}")
        return None

    # 3️⃣ Read encrypted file
    try:
        print(f"📂 Reading encrypted file from: {encrypted_file_path}")
        with open(encrypted_file_path, "rb") as f:
            file_bytes = f.read()
        print(f"✅ File read successfully, size: {len(file_bytes)} bytes")
    except FileNotFoundError:
        print(f"❌ Encrypted file not found: {encrypted_file_path}")
        return None
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None

    # 4️⃣ Parse hybrid file
    try:
        print("🔐 Parsing hybrid file format...")
        idx = 0
        rsa_key_len = int.from_bytes(file_bytes[idx:idx+4], 'big'); idx += 4
        print(f"   RSA key length: {rsa_key_len}")
        encrypted_aes_key = file_bytes[idx:idx+rsa_key_len]; idx += rsa_key_len

        nonce_len = int.from_bytes(file_bytes[idx:idx+2], 'big'); idx += 2
        print(f"   Nonce length: {nonce_len}")
        nonce = file_bytes[idx:idx+nonce_len]; idx += nonce_len

        tag_len = int.from_bytes(file_bytes[idx:idx+2], 'big'); idx += 2
        print(f"   Tag length: {tag_len}")
        tag = file_bytes[idx:idx+tag_len]; idx += tag_len

        ciphertext = file_bytes[idx:]
        print(f"   Ciphertext length: {len(ciphertext)} bytes")
        print("✅ Hybrid file parsed successfully")
    except Exception as e:
        print(f"❌ Failed to parse hybrid file: {e}")
        return None

    # 5️⃣ Decrypt AES key with RSA
    try:
        print("🔑 Decrypting AES key with RSA private key...")
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        print(f"✅ AES key decrypted successfully, length: {len(aes_key)} bytes")
    except ValueError as e:
        print(f"❌ Failed to decrypt AES key: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error during AES key decryption: {e}")
        return None

    # 6️⃣ Decrypt file with AES
    try:
        print("🔐 Decrypting file content with AES...")
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print(f"✅ File decrypted successfully, bytes: {len(decrypted_bytes)}")
    except ValueError as e:
        print(f"❌ Failed to decrypt file: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error during AES decryption: {e}")
        return None

    # 7️⃣ Save decrypted file
    try:
        user_output_dir = Path(output_dir) / user_id
        user_output_dir.mkdir(parents=True, exist_ok=True)
        original_filename = Path(encrypted_file_path).name.replace(".enc", "")
        output_path = user_output_dir / original_filename

        with open(output_path, "wb") as f:
            f.write(decrypted_bytes)

        print(f"✅ File decrypted and saved to: {output_path}")
        return output_path
    except Exception as e:
        print(f"❌ Failed to save decrypted file: {e}")
        return None
