"""Let's Encrypt DNS plugin constants."""


CLI_DEFAULTS = dict(
    server="localhost",
    server_port=53,
)
"""CLI defaults."""


TTL = 60
"""TTL, in seconds, for the "challenge domain" TXT record."""

SOURCE_PORT = 0
"""Port to issue DNS queries from."""

TIMEOUT = 30
"""Timeout, in seconds, for DNS requests."""
