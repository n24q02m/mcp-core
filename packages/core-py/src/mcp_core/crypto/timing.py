import hmac


def timing_safe_equal(a: bytes, b: bytes) -> bool:
    """Compare two byte strings safely, mitigating length-leaking timing attacks.

    hmac.compare_digest returns early if lengths differ, which leaks the
    length of the secret. This ensures compare_digest is always called with
    equal-length inputs, hiding the true length of the secret.
    """
    is_length_equal = len(a) == len(b)
    compare_b = b if is_length_equal else a
    return hmac.compare_digest(a, compare_b) and is_length_equal
