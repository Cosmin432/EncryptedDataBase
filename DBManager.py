import psycopg2
from datetime import datetime
from key_fs_manager import save_private_key, save_public_key
from psycopg2 import *
import hashlib
from pathlib import Path

class Database:
    def __init__(self):
        self.conn = psycopg2.connect(
            host="localhost",
            port=5432,
            user="postgres",
            password="admin",
            database="encrypteddb"
        )

    def get_user_password(self, username):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash FROM my_schema.users WHERE username=%s",
                (username,)
            )
            result = cursor.fetchone()
            if result:
                return result[0]
            return None

    def insert_key(self, user_id: str, public_key: str, encrypted_private_key: str, salt: str,
                   algorithm: str = "RSA-2048"):

        import uuid

        try:
            with self.conn.cursor() as cursor:
                key_id = str(uuid.uuid4())

                cursor.execute("""
                               INSERT INTO my_schema.keys (key_id, user_id, public_key, encrypted_private_key,
                                                           salt, algorithm, is_active)
                               VALUES (%s, %s, %s, %s, %s, %s, TRUE) RETURNING key_id
                               """, (key_id, user_id, public_key, encrypted_private_key, salt, algorithm))

                self.conn.commit()
                result = cursor.fetchone()

                print(f"✅ Key inserted with ID: {result[0]}")
                save_private_key(user_id, encrypted_private_key)
                save_public_key(user_id, public_key)
                return result[0]

        except Exception as e:
            print(f"❌ Failed to insert key: {e}")
            self.conn.rollback()
            return None

    def get_active_public_key(self, user_id: str) -> str:

        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                               SELECT public_key
                               FROM my_schema.keys
                               WHERE user_id = %s
                                 AND is_active = TRUE
                               ORDER BY created_at DESC LIMIT 1
                               """, (user_id,))
                result = cursor.fetchone()
                if not result:
                    raise Exception(f"❌ No active public key found for user {user_id}")
                return result[0]
        except Exception as e:
            print(f"❌ Failed to fetch public key: {e}")
            return None

    def insert_file_metadata(self, user_id: str, key_id: str, original_file_path: str,
                             encrypted_file_path: str, shard_path: str = None) -> str:

        import uuid
        try:
            file_id = str(uuid.uuid4())
            original_filename = Path(original_file_path).name
            original_size = Path(original_file_path).stat().st_size
            encrypted_size = Path(encrypted_file_path).stat().st_size

            # Calculate checksums
            def sha256_checksum(file_path):
                h = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        h.update(chunk)
                return h.hexdigest()

            original_checksum = sha256_checksum(original_file_path)
            encrypted_checksum = sha256_checksum(encrypted_file_path)

            encrypted_at = datetime.utcnow()

            with self.conn.cursor() as cursor:
                cursor.execute("""
                               INSERT INTO my_schema.files
                               (file_id, user_id, key_id, original_filename, original_size,
                                encrypted_size, encrypted_file_path, shard_path,
                                original_checksum, encrypted_checksum, encrypted_at)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING file_id
                               """, (
                                   file_id, user_id, key_id, original_filename, original_size,
                                   encrypted_size, encrypted_file_path, shard_path,
                                   original_checksum, encrypted_checksum, encrypted_at
                               ))
                self.conn.commit()
                result = cursor.fetchone()
                print(f"✅ File metadata inserted with ID: {result[0]}")
                return result[0]

        except Exception as e:
            print(f"❌ Failed to insert file metadata: {e}")
            self.conn.rollback()
            return None

    def close(self):
        self.conn.close()