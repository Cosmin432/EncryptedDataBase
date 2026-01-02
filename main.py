"""
Command-line interface for encrypted file management.

This module provides a simple CLI for encrypting, decrypting,
listing, and deleting encrypted files using a hybrid RSA + AES
encryption scheme backed by a database.
"""

import sys

from DBManager import Database
from KeyGenerator import KeyGenerator
from rsa_encrypth import encrypt_file_hybrid
from rsa_decrypt import decrypt_file_hybrid
from file_delete import delete_file
from read import list_encrypted_files


USER_ID = "550e8400-e29b-41d4-a716-446655440000"
DEFAULT_PASSWORD = "password123"


def print_usage() -> None:
    """
    Print usage instructions for the CLI.

    Displays the available commands and their expected arguments.
    """
    print("Usage:")
    print("  python main.py encrypt <file_path>")
    print("  python main.py decrypt <file_id>")
    print("  python main.py list")
    print("  python main.py delete <file_id>")


def get_key(db: Database) -> str | None:
    """
    Retrieve or generate an active encryption key for the user.

    If an active key already exists in the database, it is reused.
    Otherwise, a new key pair is generated and stored.

    Args:
        db: Database instance.

    Returns:
        The active key ID if available or generated successfully,
        otherwise None.
    """
    generator = KeyGenerator(db)
    key_id = db.get_active_key_id(USER_ID)

    if key_id:
        return key_id

    return generator.generate_and_store_keys(USER_ID, DEFAULT_PASSWORD)


def main() -> None:
    """
    Entry point for the CLI application.

    Parses command-line arguments and dispatches encryption,
    decryption, listing, or deletion operations.
    """
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1].lower()

    db = Database()
    key_id = get_key(db)

    if not key_id:
        print("❌ No encryption key available")
        return

    if command == "encrypt":
        if len(sys.argv) < 3:
            print("❌ Missing file path")
            return

        file_id = encrypt_file_hybrid(db, USER_ID, key_id, sys.argv[2])
        if file_id:
            print(f"✅ Encrypted. File ID: {file_id}")

    elif command == "decrypt":
        if len(sys.argv) < 3:
            print("❌ Missing file ID")
            return

        output = decrypt_file_hybrid(db, USER_ID, sys.argv[2], DEFAULT_PASSWORD)
        if output:
            print(f"✅ Decrypted to: {output}")

    elif command == "delete":
        if len(sys.argv) < 3:
            print("❌ Missing file ID")
            return

        delete_file(db, USER_ID, sys.argv[2])
        print("✅ File deleted")

    elif command == "list":
        list_encrypted_files(USER_ID)

    else:
        print("❌ Unknown command")
        print_usage()

    db.close()


if __name__ == "__main__":
    main()
