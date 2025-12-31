from pathlib import Path


def read_file_from_path(path_str: str) -> bytes:
    path = Path(path_str)

    if not path.exists():
        raise FileNotFoundError(f"❌ Path does not exist: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"❌ Path is not a file: {path}")

    return path.read_bytes()
