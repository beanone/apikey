import hashlib
import secrets
import string


def generate_api_key(length: int = 40) -> str:
    """Generate a secure random API key string.

    Args:
        length (int): Length of the API key.

    Returns:
        str: The generated API key (plaintext).
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256.

    Args:
        api_key (str): The plaintext API key.

    Returns:
        str: The hex-encoded SHA-256 hash of the API key.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()
