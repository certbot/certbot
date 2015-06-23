"""ACME errors."""
from acme.jose import errors as jose_errors


class Error(Exception):
    """Generic ACME error."""

class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""

class ClientError(Error):
    """Network error."""

class UnexpectedUpdate(ClientError):
    """Unexpected update."""
