"""
Database access layer for the encrypted file storage system.

This module provides the Database class, which encapsulates all interactions
with the PostgreSQL database, including users, encryption keys, and encrypted
file metadata.
"""

import psycopg2
from datetime import datetime
from pathlib import Path
import hashlib

from key_fs_manager import save_private_key, save_public_key


class Database:
    """
    Handles all database operations for users, keys, and encrypted files.

    This class manages a persistent PostgreSQL connection and exposes
    high-level methods for inserting, querying, updating, and deleting
    encryption-related data.
    """

    def __init__(self):
        """
        Initialize the database connection.

        Connects to the PostgreSQL database using predefined credentials.
        """
        self.conn = psycopg2.connect(
            host="localhost",
            port=5432,
            user="postgres",
            password="admin",
            database="encrypteddb"
        )

    def get_user_password(self, username: str) -> str | None:
        """
        Retrieve the stored password hash for a given user.

        Args:
            username: The username to look up.

        Returns:
            The password hash if the user exists, otherwise None.
        """
        with self.conn.cursor() as cursor:
            cursor.execute(
                "SELECT password_hash FROM my_schema.users WHERE username=%s",
                (username,)
            )
            result = cursor.fetchone()
            return result[0] if result else None

    def insert_key(
        self,
        user_id: str,
        public_key: str,
        encrypted_private_key: str,
        salt: str,
        algorithm: str = "RSA-2048"
    ) -> str | None:
        """
        Insert a new encryption key pair for a user.

        The key is marked as active and stored both in the database and
        on disk via the key_fs_manager.

        Args:
            user_id: UUID of the user.
            public_key: Public key in PEM format.
            encrypted_private_key: Encrypted private key.
            salt: Salt used for private key encryption.
            algorithm: Encryption algorithm identifier.

        Returns:
            The generated key_id if successful, otherwise None.
        """
        import uuid

        try:
            with self.conn.cursor() as cursor:
                key_id = str(uuid.uuid4())

                cursor.execute("""
                    INSERT INTO my_schema.keys (
                        key_id, user_id, public_key,
                        encrypted_private_key, salt,
                        algorithm, is_active
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                    RETURNING key_id
                """, (
                    key_id, user_id, public_key,
                    encrypted_private_key, salt, algorithm
                ))

                result = cursor.fetchone()
                self.conn.commit()

                save_private_key(user_id, encrypted_private_key)
                save_public_key(user_id, public_key)

                return result[0]

        except Exception as e:
            print(f"❌ Failed to insert key: {e}")
            self.conn.rollback()
            return None

    def get_active_public_key(self, user_id: str) -> str | None:
        """
        Fetch the currently active public key for a user.

        Args:
            user_id: UUID of the user.

        Returns:
            The public key as a string, or None if not found.
        """
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT public_key
                    FROM my_schema.keys
                    WHERE user_id = %s AND is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
                result = cursor.fetchone()
                return result[0] if result else None

        except Exception as e:
            print(f"❌ Failed to fetch public key: {e}")
            return None

    def insert_file_metadata(
        self,
        user_id: str,
        key_id: str,
        original_file_path: str,
        encrypted_file_path: str,
        shard_path: str | None = None
    ) -> str | None:
        """
        Insert metadata for an encrypted file.

        Stores file sizes, checksums, encryption timestamp, and paths.

        Args:
            user_id: UUID of the file owner.
            key_id: UUID of the encryption key used.
            original_file_path: Path to the original file.
            encrypted_file_path: Path to the encrypted .enc file.
            shard_path: Optional shard storage path.

        Returns:
            The generated file_id if successful, otherwise None.
        """
        import uuid

        def sha256_checksum(path: str) -> str:
            """Compute SHA-256 checksum for a file."""
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()

        try:
            file_id = str(uuid.uuid4())
            original_path = Path(original_file_path)
            encrypted_path = Path(encrypted_file_path)

            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO my_schema.files (
                        file_id, user_id, key_id,
                        original_filename, original_size,
                        encrypted_size, encrypted_file_path,
                        shard_path, original_checksum,
                        encrypted_checksum, encrypted_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING file_id
                """, (
                    file_id,
                    user_id,
                    key_id,
                    original_path.name,
                    original_path.stat().st_size,
                    encrypted_path.stat().st_size,
                    encrypted_file_path,
                    shard_path,
                    sha256_checksum(original_file_path),
                    sha256_checksum(encrypted_file_path),
                    datetime.utcnow()
                ))

                result = cursor.fetchone()
                self.conn.commit()
                return result[0]

        except Exception as e:
            print(f"❌ Failed to insert file metadata: {e}")
            self.conn.rollback()
            return None

    def get_file_decryption_info(self, user_id: str, file_id: str) -> dict | None:
        """
        Retrieve all information required to decrypt a file.

        Args:
            user_id: UUID of the requesting user.
            file_id: UUID of the encrypted file.

        Returns:
            Dictionary containing encrypted file path, encrypted private key,
            and salt, or None if not found.
        """
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT encrypted_file_path
                    FROM my_schema.files
                    WHERE file_id = %s AND user_id = %s
                """, (file_id, user_id))
                file_row = cursor.fetchone()
                if not file_row:
                    return None

                cursor.execute("""
                    SELECT encrypted_private_key, salt
                    FROM my_schema.keys
                    WHERE user_id = %s AND is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
                key_row = cursor.fetchone()
                if not key_row:
                    return None

                return {
                    "encrypted_file_path": file_row[0],
                    "encrypted_private_key": key_row[0],
                    "salt": key_row[1],
                }

        except Exception as e:
            print(f"❌ Failed to fetch decryption info: {e}")
            return None

    def get_active_key_id(self, user_id: str) -> str | None:
        """
        Retrieve the active key ID for a user.

        Args:
            user_id: UUID of the user.

        Returns:
            The active key_id or None if not found.
        """
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    SELECT key_id
                    FROM my_schema.keys
                    WHERE user_id = %s AND is_active = TRUE
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (user_id,))
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            print(f"❌ Failed to fetch active key ID: {e}")
            return None

    def delete_file_metadata(self, user_id: str, file_id: str) -> bool:
        """
        Delete encrypted file metadata from the database.

        Args:
            user_id: UUID of the file owner.
            file_id: UUID of the file.

        Returns:
            True if deletion succeeded, False otherwise.
        """
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM my_schema.files
                    WHERE file_id = %s AND user_id = %s
                    RETURNING encrypted_file_path
                """, (file_id, user_id))

                if not cursor.fetchone():
                    return False

                self.conn.commit()
                return True

        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to delete metadata: {e}")
            return False

    def update_file_path(self, file_id: str, new_path: str) -> bool:
        """
        Update the encrypted file path for a given file ID.

        Args:
            file_id: UUID of the encrypted file.
            new_path: New filesystem path to the .enc file.

        Returns:
            True if the update was successful, False otherwise.
        """
        try:
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE my_schema.files
                    SET encrypted_file_path = %s
                    WHERE file_id = %s
                """, (new_path, file_id))
                self.conn.commit()
            return True

        except Exception as e:
            self.conn.rollback()
            print(f"❌ Failed to update DB path: {e}")
            return False

    def close(self):
        """
        Close the database connection.
        """
        self.conn.close()
