from pathlib import Path

def list_encrypted_files(user_id: str, base_dir="data/files"):
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
