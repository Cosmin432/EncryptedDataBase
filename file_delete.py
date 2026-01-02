from DBManager import Database
from secure_delete import secure_wipe_file

def delete_file(db: Database, user_id: str, file_id: str) -> bool:

    print(f"\nStarting deletion for file_id: {file_id}")

    # 1️⃣ Fetch encrypted file path
    info = db.get_file_decryption_info(user_id, file_id)
    if not info:
        print("❌ File not found or access denied")
        return False

    encrypted_file_path = info["encrypted_file_path"]

    # 2️⃣ Secure wipe file
    if not secure_wipe_file(encrypted_file_path):
        print("❌ File wipe failed — aborting DB delete")
        return False

    # 3️⃣ Delete DB metadata
    if not db.delete_file_metadata(user_id, file_id):
        print("⚠️ File deleted but metadata cleanup failed")
        return False

    print("✅ File and metadata fully deleted")
    return True
