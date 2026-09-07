import missing_v01_dependency


def normalize_customer_name(value: str) -> str:
    """Normalize a customer name through an unavailable dependency."""
    return missing_v01_dependency.clean(value)
