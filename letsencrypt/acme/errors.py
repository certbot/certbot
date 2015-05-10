"""ACME errors."""
from letsencrypt.acme.jose import errors as jose_errors

class Error(Exception):
    """Generic ACME error."""

class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""
