"""ACME interfaces."""
from acme import jose


class ClientRequestableResource(jose.JSONDeSerializable):
    """Resource that can be requested by client.

    :ivar unicode resource_type: ACME resource identifier used in client
        HTTPS requests in order to protect against MITM.

    """
    # pylint: disable=abstract-method
    resource_type = NotImplemented
