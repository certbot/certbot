"""Let's Encrypt DNS plugin constants."""


CHALLENGE_SUBDOMAIN = "_acme-challenge"
"""Challenge subdomain."""

CHALLENGE_TTL = 60
"""TTL, in seconds, for the _acme-challenge.domain TXT record."""

CHALLENGE_SOURCE_PORT = 0
"""Port to issue DNS queries from."""

CHALLENGE_TIMEOUT = 30
"""Timeout, in seconds, for DNS requests."""
