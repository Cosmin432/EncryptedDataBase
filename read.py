"""
Utility functions for inspecting encrypted files on disk.
"""

from pathlib import Path


def list_encrypted_files(user_id: str, base_dir: str = "data/files") -> None:
    """
    List encrypted `.enc` files for a specific user.

    This function scans the user's encrypted files directory and
    prints the file identifiers (derived from the `.enc` filenames).

    Args:
        user_id: UUID of the user whose encrypted files should be listed.
        base_dir: Base directory where encrypted files are stored.

    Returns:
        None
    """
    user_dir = Path(base_dir) / user_id

    if not user_dir.exists():
        print("📂 No encrypted files directory found.")
        return

    enc_files = list(user_dir.glob("*.enc"))

    if not enc_files:
        print("📭 No encrypted files found.")
        return

    print("🔐 Encrypted files:")
    for f in enc_files:
        print(f"  - {f.stem}")
