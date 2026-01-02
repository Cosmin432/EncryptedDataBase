"""
Filesystem utilities for managing cryptographic keys.

This module provides helper functions for creating the required
directory structure and storing encrypted private keys and public
keys on disk in a consistent location.
"""

from pathlib import Path

BASE_DATA_DIR = Path("data")
PRIVATE_KEYS_DIR = BASE_DATA_DIR / "private"
PUBLIC_KEYS_DIR = BASE_DATA_DIR / "public"


def ensure_dirs() -> None:
    """
    Ensure that the key storage directories exist.

    This function creates the base directory structure used for
    storing private and public keys if it does not already exist.
    """
    PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_KEYS_DIR.mkdir(parents=True, exist_ok=True)


def save_private_key(user_id: str, encrypted_private_key: str) -> None:
    """
    Save an encrypted private key to disk for a given user.

    The private key is stored under the private keys directory
    using the user's ID as the filename.

    Args:
        user_id: Unique identifier of the user.
        encrypted_private_key: The encrypted private key in PEM format.
    """
    ensure_dirs()

    private_key_path = PRIVATE_KEYS_DIR / f"{user_id}.pem"

    with open(private_key_path, "w", encoding="utf-8") as f:
        f.write(encrypted_private_key)


def save_public_key(user_id: str, public_key: str) -> None:
    """
    Save a public key to disk for a given user.

    The public key is stored under the public keys directory
    using the user's ID as the filename.

    Args:
        user_id: Unique identifier of the user.
        public_key: The public key in PEM format.
    """
    ensure_dirs()

    public_key_path = PUBLIC_KEYS_DIR / f"{user_id}.pem"

    with open(public_key_path, "w", encoding="utf-8") as f:
        f.write(public_key)
