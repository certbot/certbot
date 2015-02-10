"""ACME errors."""

class Error(Exception):
    """Generic ACME error."""

class ValidationError(Error):
    """ACME message validation error."""

class UnrecognizedMessageTypeError(ValidationError):
    """Unrecognized ACME message type error."""

class SchemaValidationError(ValidationError):
    """JSON schema ACME message validation error."""
