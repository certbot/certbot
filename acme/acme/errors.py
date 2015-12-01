"""ACME errors."""
from acme.jose import errors as jose_errors


class Error(Exception):
    """Generic ACME error."""


class SchemaValidationError(jose_errors.DeserializationError):
    """JSON schema ACME object validation error."""


class ClientError(Error):
    """Network error."""


class UnexpectedUpdate(ClientError):
    """Unexpected update error."""


class NonceError(ClientError):
    """Server response nonce error."""


class BadNonce(NonceError):
    """Bad nonce error."""
    def __init__(self, nonce, error, *args, **kwargs):
        super(BadNonce, self).__init__(*args, **kwargs)
        self.nonce = nonce
        self.error = error

    def __str__(self):
        return 'Invalid nonce ({0!r}): {1}'.format(self.nonce, self.error)


class MissingNonce(NonceError):
    """Missing nonce error.

    According to the specification an "ACME server MUST include an
    Replay-Nonce header field in each successful response to a POST it
    provides to a client (...)".

    :ivar requests.Response response: HTTP Response

    """
    def __init__(self, response, *args, **kwargs):
        super(MissingNonce, self).__init__(*args, **kwargs)
        self.response = response

    def __str__(self):
        return ('Server {0} response did not include a replay '
                'nonce, headers: {1}'.format(
                    self.response.request.method, self.response.headers))


class PollError(ClientError):
    """Generic error when polling for authorization fails.

    This might be caused by either timeout (`waiting` will be non-empty)
    or by some authorization being invalid.

    :ivar waiting: Priority queue with `datetime.datatime` (based on
        ``Retry-After``) as key, and original `.AuthorizationResource`
        as value.
    :ivar updated: Mapping from original `.AuthorizationResource`
        to the most recently updated one

    """
    def __init__(self, waiting, updated):
        self.waiting = waiting
        self.updated = updated
        super(PollError, self).__init__()

    @property
    def timeout(self):
        """Was the error caused by timeout?"""
        return bool(self.waiting)

    def __repr__(self):
        return '{0}(waiting={1!r}, updated={2!r})'.format(
            self.__class__.__name__, self.waiting, self.updated)
