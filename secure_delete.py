import os
import secrets

def secure_wipe_file(path: str, passes: int = 3):

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
