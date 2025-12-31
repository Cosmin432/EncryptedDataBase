from pathlib import Path

BASE_DATA_DIR = Path("data")
PRIVATE_KEYS_DIR = BASE_DATA_DIR / "private"
PUBLIC_KEYS_DIR = BASE_DATA_DIR / "public"


def ensure_dirs():
    PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_KEYS_DIR.mkdir(parents=True, exist_ok=True)


def save_private_key(user_id: str, encrypted_private_key: str):

    ensure_dirs()

    private_key_path = PRIVATE_KEYS_DIR / f"{user_id}.pem"

    with open(private_key_path, "w", encoding="utf-8") as f:
        f.write(encrypted_private_key)



def save_public_key(user_id: str, public_key: str):

    ensure_dirs()

    public_key_path = PUBLIC_KEYS_DIR / f"{user_id}.pem"

    with open(public_key_path, "w", encoding="utf-8") as f:
        f.write(public_key)
