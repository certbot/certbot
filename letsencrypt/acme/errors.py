"""ACME errors."""

class Error(Exception):
    """Generic ACME error."""

class ValidationError(Error):
    """ACME object validation error."""

class UnrecognizedTypeError(ValidationError):
    """Unrecognized ACME object type error."""

class SchemaValidationError(ValidationError):
    """JSON schema ACME object validation error."""
