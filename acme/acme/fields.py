"""ACME JSON fields."""
import logging

import pyrfc3339

from acme import jose


logger = logging.getLogger(__name__)


class Fixed(jose.Field):
    """Fixed field."""

    def __init__(self, json_name, value):
        self.value = value
        super(Fixed, self).__init__(
            json_name=json_name, default=value, omitempty=False)

    def decode(self, value):
        if value != self.value:
            raise jose.DeserializationError('Expected {0!r}'.format(self.value))
        return self.value

    def encode(self, value):
        if value != self.value:
            logger.warning(
                'Overriding fixed field (%s) with %r', self.json_name, value)
        return value


class RFC3339Field(jose.Field):
    """RFC3339 field encoder/decoder.

    Handles decoding/encoding between RFC3339 strings and aware (not
    naive) `datetime.datetime` objects
    (e.g. ``datetime.datetime.now(pytz.utc)``).

    """

    @classmethod
    def default_encoder(cls, value):
        return pyrfc3339.generate(value)

    @classmethod
    def default_decoder(cls, value):
        try:
            return pyrfc3339.parse(value)
        except ValueError as error:
            raise jose.DeserializationError(error)


class Resource(jose.Field):
    """Resource MITM field."""

    def __init__(self, resource_type, *args, **kwargs):
        self.resource_type = resource_type
        super(Resource, self).__init__(
            'resource', default=resource_type, *args, **kwargs)

    def decode(self, value):
        if value != self.resource_type:
            raise jose.DeserializationError(
                'Wrong resource type: {0} instead of {1}'.format(
                    value, self.resource_type))
        return value
