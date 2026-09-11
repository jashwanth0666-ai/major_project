import hashlib
from pathlib import Path


class ModelIntegrityError(RuntimeError):
    """Raised when the model artifact cannot be trusted."""


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    if not path.is_file():
        raise ModelIntegrityError(f"Model file not found: {path}")

    digest = hashlib.sha256()

    try:
        with path.open("rb") as file:
            while chunk := file.read(chunk_size):
                digest.update(chunk)
    except OSError as exc:
        raise ModelIntegrityError(
            f"Unable to read model file: {path}"
        ) from exc

    return digest.hexdigest().lower()


def verify_model(path: Path, expected_sha256: str) -> str:
    expected = expected_sha256.strip().lower()

    if len(expected) != 64 or any(
        char not in "0123456789abcdef" for char in expected
    ):
        raise ModelIntegrityError("Configured model SHA-256 is invalid.")

    actual = sha256_file(path)

    if actual != expected:
        raise ModelIntegrityError(
            "Model integrity verification failed. "
            f"Expected SHA-256: {expected}; actual SHA-256: {actual}"
        )

    return actual
