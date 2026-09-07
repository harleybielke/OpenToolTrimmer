import helpers


def normalize_customer_name(value: str) -> str:
    """Normalize a customer name for cleanup."""
    return helpers.normalize_name(value)
