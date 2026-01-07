import os
import sys
import pytest
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from DBManager import Database
from rsa_encrypth import encrypt_file_hybrid
from rsa_decrypt import decrypt_file_hybrid
from KeyGenerator import KeyGenerator

USER_ID = "550e8400-e29b-41d4-a716-446655440000"
PASSWORD = "password123"


@pytest.fixture
def db():
    """Create a fresh database instance for each test."""
    database = Database()
    yield database
    database.close()


@pytest.fixture
def setup_key(db):
    """Generate encryption key for tests."""
    generator = KeyGenerator(db)
    key_id = generator.generate_and_store_keys(USER_ID, PASSWORD)
    return key_id


@pytest.fixture
def test_file(tmp_path):
    """Create a test file with content."""
    content = "Hello, this is a test file 🔐"
    file_path = tmp_path / "test.txt"
    file_path.write_text(content, encoding="utf-8")
    return file_path, content


def test_encrypt_file_success(db, setup_key, test_file):
    """Test successful file encryption."""
    key_id = setup_key
    file_path, _ = test_file

    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(file_path))

    assert file_id is not None
    assert isinstance(file_id, str)


def test_decrypt_file_success(db, setup_key, test_file):
    """Test successful file decryption."""
    key_id = setup_key
    file_path, original_content = test_file

    # Encrypt first
    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(file_path))
    assert file_id is not None

    # Decrypt
    decrypted_path = decrypt_file_hybrid(db, USER_ID, file_id, PASSWORD)

    assert decrypted_path is not None
    assert os.path.exists(decrypted_path)

    # Verify content integrity
    with open(decrypted_path, "r", encoding="utf-8") as f:
        decrypted_content = f.read()

    assert decrypted_content == original_content

    # Cleanup decrypted file
    if os.path.exists(decrypted_path):
        os.remove(decrypted_path)


def test_encrypt_decrypt_roundtrip(db, setup_key, test_file):
    """Test complete encrypt-decrypt cycle."""
    key_id = setup_key
    file_path, original_content = test_file

    # Encrypt
    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(file_path))
    assert file_id is not None, "Encryption failed"

    # Decrypt
    decrypted_path = decrypt_file_hybrid(db, USER_ID, file_id, PASSWORD)
    assert decrypted_path is not None, "Decryption failed"

    # Verify
    with open(decrypted_path, "r", encoding="utf-8") as f:
        assert f.read() == original_content

    # Cleanup
    if os.path.exists(decrypted_path):
        os.remove(decrypted_path)


def test_encrypt_nonexistent_file(db, setup_key):
    """Test encryption with non-existent file raises FileNotFoundError."""
    key_id = setup_key

    # Funcția aruncă excepție, nu returnează None
    with pytest.raises(FileNotFoundError):
        encrypt_file_hybrid(db, USER_ID, key_id, "/path/to/nonexistent/file.txt")


def test_decrypt_invalid_file_id(db, setup_key):
    """Test decryption with invalid file ID."""
    decrypted_path = decrypt_file_hybrid(db, USER_ID, "invalid-file-id-12345", PASSWORD)

    assert decrypted_path is None


def test_decrypt_wrong_password(db, setup_key, test_file):
    """Test decryption with wrong password."""
    key_id = setup_key
    file_path, _ = test_file

    # Encrypt
    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(file_path))
    assert file_id is not None

    # Try decrypt with wrong password - ar trebui să eșueze
    decrypted_path = decrypt_file_hybrid(db, USER_ID, file_id, "wrong_password")

    # Verifică că a eșuat (fie None, fie excepție)
    assert decrypted_path is None or not os.path.exists(decrypted_path)


def test_encrypt_large_file(db, setup_key, tmp_path):
    """Test encryption of larger file."""
    # Create a larger test file (100KB - mai mic pentru teste rapide)
    large_content = "A" * (100 * 1024)
    large_file = tmp_path / "large.txt"
    large_file.write_text(large_content)

    key_id = setup_key

    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(large_file))
    assert file_id is not None

    decrypted_path = decrypt_file_hybrid(db, USER_ID, file_id, PASSWORD)
    assert decrypted_path is not None

    with open(decrypted_path, "r", encoding="utf-8") as f:
        assert f.read() == large_content

    # Cleanup
    if os.path.exists(decrypted_path):
        os.remove(decrypted_path)


def test_encrypt_binary_file(db, setup_key, tmp_path):
    """Test encryption of binary file."""
    binary_content = bytes([i % 256 for i in range(1000)])
    binary_file = tmp_path / "test.bin"
    binary_file.write_bytes(binary_content)

    key_id = setup_key

    file_id = encrypt_file_hybrid(db, USER_ID, key_id, str(binary_file))
    assert file_id is not None

    decrypted_path = decrypt_file_hybrid(db, USER_ID, file_id, PASSWORD)
    assert decrypted_path is not None

    with open(decrypted_path, "rb") as f:
        assert f.read() == binary_content

    # Cleanup
    if os.path.exists(decrypted_path):
        os.remove(decrypted_path)