import os
import secrets

def secure_wipe_file(path: str, passes: int = 3) -> bool:
    """
    Securely overwrite and delete a file from disk.

    This function overwrites the file's content with random bytes multiple times
    (default: 3 passes) to make recovery difficult, then deletes the file.

    Args:
        path: The file path to securely delete.
        passes: Number of overwrite passes (default is 3).

    Returns:
        bool: True if the file was successfully wiped and deleted, False otherwise.

    Notes:
        - Prints progress messages for each overwrite pass.
        - Uses `secrets.token_bytes` for cryptographically secure random data.
        - Flushes and synchronizes writes to disk to ensure data is actually written.
        - If the file does not exist, returns False.
    """
    if not os.path.exists(path):
        print("❌ File does not exist")
        return False

    size = os.path.getsize(path)

    try:
        with open(path, "r+b") as f:
            for i in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
                print(f"🔁 Overwrite pass {i + 1}/{passes}")

        os.remove(path)
        print("🗑 File securely deleted from disk")
        return True

    except Exception as e:
        print(f"❌ Secure delete failed: {e}")
        return False
