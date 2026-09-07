from helpers import normalize_name


def normalize_customer_name(value: str) -> str:
    """Normalize a customer name for cleanup."""
    return normalize_name(value)
