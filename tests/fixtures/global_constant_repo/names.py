PREFIX = "customer_"


def make_customer_name(value: str) -> str:
    """Build a customer name using a module-level prefix."""
    return PREFIX + value
