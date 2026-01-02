"""
File reading utilities.

This module provides helper functions for safely reading files
from disk with basic validation.
"""

from pathlib import Path


def read_file_from_path(path_str: str) -> bytes:
    """
    Read a file from disk and return its contents as bytes.

    The function validates that the provided path exists and points
    to a regular file before attempting to read it.

    Args:
        path_str: Path to the file as a string.

    Returns:
        The contents of the file as a bytes object.

    Raises:
        FileNotFoundError: If the path does not exist.
        IsADirectoryError: If the path exists but is not a file.
    """
    path = Path(path_str)

    if not path.exists():
        raise FileNotFoundError(f"❌ Path does not exist: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"❌ Path is not a file: {path}")

    return path.read_bytes()
