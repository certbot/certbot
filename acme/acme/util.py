"""ACME utilities."""


def map_keys(dikt, func):
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}
