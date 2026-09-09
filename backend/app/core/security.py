import hashlib
import hmac

def hash_file_sha256(data: bytes) -> str:
    """Generate SHA-256 hash for forensic digital evidence."""
    return hashlib.sha256(data).hexdigest()

def hash_string_sha256(text: str) -> str:
    """Generate SHA-256 hash for structured metadata or query strings."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def verify_data_integrity(data: bytes, expected_hash: str) -> bool:
    """Verify raw bytes match the expected SHA-256 hash."""
    computed_hash = hash_file_sha256(data)
    return hmac.compare_digest(computed_hash.lower(), expected_hash.lower())
