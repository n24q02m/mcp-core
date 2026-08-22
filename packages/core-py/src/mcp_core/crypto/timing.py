import hmac


def timing_safe_equal(a: bytes | str, b: bytes | str) -> bool:
    """Compare two byte strings or strings safely, mitigating length-leaking timing attacks.

    hmac.compare_digest and secrets.compare_digest return early if lengths differ,
    which leaks the length of the secret. This ensures compare_digest is always
    called with equal-length inputs, hiding the true length of the secret.
    """
    a_bytes = a if isinstance(a, bytes) else a.encode("utf-8")
    b_bytes = b if isinstance(b, bytes) else b.encode("utf-8")

    is_length_equal = len(a_bytes) == len(b_bytes)
    compare_b = b_bytes if is_length_equal else a_bytes
    return hmac.compare_digest(a_bytes, compare_b) and is_length_equal
