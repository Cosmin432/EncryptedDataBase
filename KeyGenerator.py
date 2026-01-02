"""
Key generation and key protection utilities.

This module provides functionality for generating RSA key pairs,
encrypting and decrypting private keys using password-based key
derivation, and storing the resulting keys via a database backend.
"""

import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class KeyGenerator:
    """
    Handles RSA key generation, encryption, decryption, and storage.

    This class is responsible for:
    - Generating RSA key pairs
    - Encrypting private keys using a password
    - Decrypting private keys for use
    - Persisting keys through a database interface
    """

    def __init__(self, db, key_size: int = 2048):
        """
        Initialize the key generator.

        Args:
            db: Database instance used for key storage.
            key_size: RSA key size in bits (default: 2048).
        """
        self.key_size = key_size
        self.algorithm = f"RSA-{key_size}"
        self.db = db

    def generate_key_pair(self) -> tuple[str, str]:
        """
        Generate an RSA public/private key pair.

        Returns:
            A tuple containing:
            - public_key_pem: Public key in PEM format.
            - private_key_pem: Private key in PEM format.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        print("✅ Key pair generated successfully")
        return public_key_pem, private_key_pem

    @staticmethod
    def derive_encryption_key(password: str, salt: bytes) -> bytes:
        """
        Derive a symmetric encryption key from a password.

        PBKDF2-HMAC-SHA256 is used to derive a key suitable for Fernet
        encryption.

        Args:
            password: User-provided password.
            salt: Random salt value.

        Returns:
            A URL-safe base64-encoded encryption key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_private_key(private_key_pem: str, password: str) -> tuple[str, str]:
        """
        Encrypt a private key using a password.

        The private key is encrypted using Fernet after deriving
        a symmetric key from the password.

        Args:
            private_key_pem: Private key in PEM format.
            password: Password used for encryption.

        Returns:
            A tuple containing:
            - encrypted_private_key_b64: Encrypted private key (base64).
            - salt_hex: Salt used during key derivation (hex-encoded).
        """
        print("🔒 Encrypting private key...")

        salt = os.urandom(32)
        encryption_key = KeyGenerator.derive_encryption_key(password, salt)

        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(private_key_pem.encode())

        encrypted_private_key_b64 = base64.b64encode(encrypted_data).decode("utf-8")
        salt_hex = salt.hex()

        print("✅ Private key encrypted")
        return encrypted_private_key_b64, salt_hex

    @staticmethod
    def decrypt_private_key(
        encrypted_private_key_b64: str,
        password: str,
        salt_hex: str
    ) -> str:
        """
        Decrypt an encrypted private key using a password.

        Args:
            encrypted_private_key_b64: Encrypted private key (base64).
            password: Password used during encryption.
            salt_hex: Salt used during key derivation (hex-encoded).

        Returns:
            The decrypted private key in PEM format.

        Raises:
            cryptography.fernet.InvalidToken: If decryption fails.
        """
        print("🔓 Decrypting private key...")

        encrypted_data = base64.b64decode(encrypted_private_key_b64)
        salt = bytes.fromhex(salt_hex)

        encryption_key = KeyGenerator.derive_encryption_key(password, salt)
        fernet = Fernet(encryption_key)

        private_key_pem = fernet.decrypt(encrypted_data).decode("utf-8")

        print("✅ Private key decrypted")
        return private_key_pem

    def generate_and_encrypt(self, password: str) -> dict:
        """
        Generate a key pair and encrypt the private key.

        Args:
            password: Password used to encrypt the private key.

        Returns:
            Dictionary containing:
            - public_key
            - encrypted_private_key
            - salt
            - algorithm
        """
        public_key, private_key = self.generate_key_pair()
        encrypted_private_key, salt = self.encrypt_private_key(private_key, password)

        return {
            "public_key": public_key,
            "encrypted_private_key": encrypted_private_key,
            "salt": salt,
            "algorithm": self.algorithm
        }

    def generate_and_store_keys(self, user_id: str, password: str) -> str | None:
        """
        Generate, encrypt, and store keys for a user.

        Args:
            user_id: Unique identifier of the user.
            password: Password used to encrypt the private key.

        Returns:
            The generated key ID if successful, otherwise None.
        """
        print(f"\n🔑 Generating and storing keys for user: {user_id}")

        try:
            keys = self.generate_and_encrypt(password)

            key_id = self.db.insert_key(
                user_id=user_id,
                public_key=keys["public_key"],
                encrypted_private_key=keys["encrypted_private_key"],
                salt=keys["salt"],
                algorithm=keys["algorithm"]
            )

            if key_id:
                print(f"✅ Keys successfully stored with ID: {key_id}")
                return key_id

            print("❌ Failed to store keys in database")
            return None

        except Exception as e:
            print(f"❌ Error generating/storing keys: {e}")
            return None

    def test_key_generation(self) -> None:
        """
        Run a full test of key generation, encryption, and decryption.

        This method:
        - Generates and encrypts a key pair
        - Decrypts the private key with the correct password
        - Verifies that decryption fails with an incorrect password
        """
        test_password = self.db.get_user_password("test_user")

        if not test_password:
            print("❌ Test user not found!")
            return

        keys = self.generate_and_encrypt(test_password)

        print("\n📊 Results:")
        print(f"   Algorithm: {keys['algorithm']}")
        print(f"   Public key length: {len(keys['public_key'])} chars")
        print(f"   Encrypted private key length: {len(keys['encrypted_private_key'])} chars")
        print(f"   Salt length: {len(keys['salt'])} chars")

        print("\nStep 2: Test decryption")
        try:
            decrypted_private_key = KeyGenerator.decrypt_private_key(
                keys["encrypted_private_key"],
                test_password,
                keys["salt"]
            )

            if "BEGIN PRIVATE KEY" in decrypted_private_key:
                print("✅ Decryption successful - Valid PEM format")
            else:
                print("❌ Decryption failed - Invalid format")

        except Exception as e:
            print(f"❌ Decryption failed: {e}")

        print("\nStep 3: Test with wrong password")
        try:
            KeyGenerator.decrypt_private_key(
                keys["encrypted_private_key"],
                "wrong_password",
                keys["salt"]
            )
            print("❌ Security issue - wrong password worked!")
        except Exception:
            print("✅ Security check passed - wrong password rejected")

        print("\n" + "=" * 60)
        print("✅ KEY GENERATOR TEST COMPLETE")
        print("=" * 60 + "\n")
