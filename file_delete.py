"""
File deletion logic for encrypted files.

This module provides functionality to securely delete encrypted files
from disk and remove their corresponding metadata from the database.
"""

from DBManager import Database
from secure_delete import secure_wipe_file


def delete_file(db: Database, user_id: str, file_id: str) -> bool:
    """
    Securely delete an encrypted file and its metadata.

    This function performs a three-step deletion process:
    1. Fetches the encrypted file path from the database.
    2. Securely wipes the encrypted file from disk.
    3. Deletes the associated metadata from the database.

    The database entry is removed only if the file wipe succeeds,
    ensuring consistency between disk state and database state.

    Args:
        db: Active Database instance.
        user_id: UUID of the user requesting the deletion.
        file_id: UUID of the encrypted file to be deleted.

    Returns:
        True if both the encrypted file and its metadata were deleted
        successfully, False otherwise.
    """

    print(f"\nStarting deletion for file_id: {file_id}")

    # 1️⃣ Fetch encrypted file path
    info = db.get_file_decryption_info(user_id, file_id)
    if not info:
        print("❌ File not found or access denied")
        return False

    encrypted_file_path = info["encrypted_file_path"]

    # 2️⃣ Securely wipe encrypted file from disk
    if not secure_wipe_file(encrypted_file_path):
        print("❌ File wipe failed — aborting DB delete")
        return False

    # 3️⃣ Delete file metadata from database
    if not db.delete_file_metadata(user_id, file_id):
        print("⚠️ File deleted but metadata cleanup failed")
        return False

    print("✅ File and metadata fully deleted")
    return True
