PREFIX = "customer_"


try:
    import pathlib
except ImportError:
    pass


def make_customer_name(value: str) -> str:
    """Build a customer name using a module-level prefix."""
    return PREFIX + value
