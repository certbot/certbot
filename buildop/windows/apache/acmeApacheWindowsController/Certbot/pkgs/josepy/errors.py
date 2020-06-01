"""JOSE errors."""


class Error(Exception):
    """Generic JOSE Error."""


class DeserializationError(Error):
    """JSON deserialization error."""

    def __str__(self):
        return "Deserialization error: {0}".format(
            super(DeserializationError, self).__str__())


class SerializationError(Error):
    """JSON serialization error."""


class UnrecognizedTypeError(DeserializationError):
    """Unrecognized type error.

    :ivar str typ: The unrecognized type of the JSON object.
    :ivar jobj: Full JSON object.

    """

    def __init__(self, typ, jobj):
        self.typ = typ
        self.jobj = jobj
        super(UnrecognizedTypeError, self).__init__(str(self))

    def __str__(self):
        return '{0} was not recognized, full message: {1}'.format(
            self.typ, self.jobj)
