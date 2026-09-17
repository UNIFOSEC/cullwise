"""Intentionally insecure demo code for the ThreatLens dashboard scan. Not real."""

import hashlib


def make_token(password: str) -> str:
    # Weak hash for security purposes (CWE-327).
    return hashlib.md5(password.encode()).hexdigest()
