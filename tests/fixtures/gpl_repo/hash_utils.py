from pathlib import Path
import hashlib


def hash_file(path: str | Path) -> str:
    """Calculate a SHA256 hash for one file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_directory(root: str | Path) -> dict[str, str]:
    """Recursively hash every file below a directory."""
    base = Path(root)
    return {
        str(path.relative_to(base)): hash_file(path)
        for path in base.rglob("*")
        if path.is_file()
    }


def unrelated_banner() -> str:
    return "hello"
