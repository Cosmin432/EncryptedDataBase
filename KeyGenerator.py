from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os


class KeyGenerator:

    def __init__(self,db, key_size=2048 ):
        self.key_size = key_size
        self.algorithm = f"RSA-{key_size}"
        self.db = db
    def generate_key_pair(self):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        print("✅ Key pair generated successfully")
        return public_key_pem, private_key_pem

    @staticmethod
    def derive_encryption_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_private_key(private_key_pem: str, password: str):
        print("🔒 Encrypting private key...")

        salt = os.urandom(32)
        encryption_key = KeyGenerator.derive_encryption_key(password, salt)

        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(private_key_pem.encode())

        encrypted_private_key_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        salt_hex = salt.hex()

        print("✅ Private key encrypted")
        return encrypted_private_key_b64, salt_hex

    @staticmethod
    def decrypt_private_key(encrypted_private_key_b64: str, password: str, salt_hex: str) -> str:
        print("🔓 Decrypting private key...")

        encrypted_data = base64.b64decode(encrypted_private_key_b64)
        salt = bytes.fromhex(salt_hex)

        encryption_key = KeyGenerator.derive_encryption_key(password, salt)

        fernet = Fernet(encryption_key)
        private_key_pem = fernet.decrypt(encrypted_data).decode('utf-8')

        print("✅ Private key decrypted")
        return private_key_pem

    def generate_and_encrypt(self, password: str):
        public_key, private_key = self.generate_key_pair()
        encrypted_private_key, salt = self.encrypt_private_key(private_key, password)

        return {
            'public_key': public_key,
            'encrypted_private_key': encrypted_private_key,
            'salt': salt,
            'algorithm': self.algorithm
        }

    def test_key_generation(self):
        # folosim self.db, nu db global
        test_password = self.db.get_user_password("test_user")

        # folosim generatorul curent
        keys = self.generate_and_encrypt(test_password)

        print(f"\n📊 Results:")
        print(f"   Algorithm: {keys['algorithm']}")
        print(f"   Public key length: {len(keys['public_key'])} chars")
        print(f"   Encrypted private key length: {len(keys['encrypted_private_key'])} chars")
        print(f"   Salt length: {len(keys['salt'])} chars")

        print(f"\nStep 2: Test decryption")
        try:
            decrypted_private_key = KeyGenerator.decrypt_private_key(
                keys['encrypted_private_key'],
                test_password,
                keys['salt']
            )

            if "BEGIN PRIVATE KEY" in decrypted_private_key:
                print("✅ Decryption successful - Valid PEM format")
            else:
                print("❌ Decryption failed - Invalid format")

        except Exception as e:
            print(f"❌ Decryption failed: {e}")

        print(f"\nStep 3: Test with wrong password")
        try:
            KeyGenerator.decrypt_private_key(
                keys['encrypted_private_key'],
                "wrong_password",
                keys['salt']
            )
            print("❌ Security issue - wrong password worked!")
        except Exception:
            print("✅ Security check passed - wrong password rejected")

        print("\n" + "=" * 60)
        print("✅ KEY GENERATOR TEST COMPLETE")
        print("=" * 60 + "\n")

