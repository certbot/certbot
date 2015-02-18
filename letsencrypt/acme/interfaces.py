"""ACME interfaces."""
import zope.interface

# pylint: disable=no-self-argument,no-method-argument,no-init,inherit-non-class


class IJSONSerializable(zope.interface.Interface):
    # pylint: disable=too-few-public-methods
    """JSON serializable object."""

    def to_json():
        """Prepare JSON serializable object.

        :returns: JSON object ready to be serialized. Note, however, that
            this might return other
            :class:`letsencrypt.acme.interfaces.IJSONSerializable`
            objects, that haven't been serialized yet, which is fine as
            long as :func:`letsencrypt.acme.util.dump_ijsonserializable`
            is used.
        :rtype: dict

        """
