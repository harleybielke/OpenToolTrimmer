class NameFormatter:
    def clean(self, value: str) -> str:
        return value.strip().lower()


def normalize_customer_name(value: str) -> str:
    formatter = NameFormatter()
    return formatter.clean(value)
