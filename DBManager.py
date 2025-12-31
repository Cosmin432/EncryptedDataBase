import psycopg2
from key_fs_manager import save_private_key, save_public_key
from psycopg2 import *

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

    def close(self):
        self.conn.close()