"""ACME JSON fields."""
import pyrfc3339

from letsencrypt.acme import jose


class RFC3339Field(jose.Field):
    """RFC3339 field encoder/decoder"""

    @classmethod
    def default_encoder(self, value):
        return pyrfc3339.generate(value)

    @classmethod
    def default_decoder(cls, value):
        try:
            return pyrfc3339.parse(value)
        except ValueError as error:
            raise jose.DeserializationError(error)
