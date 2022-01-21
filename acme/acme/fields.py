"""ACME JSON fields."""
import datetime
from typing import Any

import logging

import josepy as jose
import pyrfc3339

logger = logging.getLogger(__name__)


class Fixed(jose.Field):
    """Fixed field."""

    def __init__(self, json_name: str, value: Any) -> None:
        self.value = value
        super().__init__(json_name=json_name, default=value, omitempty=False)

    def decode(self, value: Any) -> Any:
        if value != self.value:
            raise jose.DeserializationError('Expected {0!r}'.format(self.value))
        return self.value

    def encode(self, value: Any) -> Any:
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
    def default_encoder(cls, value: datetime.datetime) -> str:
        return pyrfc3339.generate(value)

    @classmethod
    def default_decoder(cls, value: str) -> datetime.datetime:
        try:
            return pyrfc3339.parse(value)
        except ValueError as error:
            raise jose.DeserializationError(error)


class Resource(jose.Field):
    """Resource MITM field."""

    def __init__(self, resource_type: str, *args: Any, **kwargs: Any) -> None:
        self.resource_type = resource_type
        kwargs['default'] = resource_type
        super().__init__('resource', *args, **kwargs)

    def decode(self, value: Any) -> Any:
        if value != self.resource_type:
            raise jose.DeserializationError(
                f'Wrong resource type: {value} instead of {self.resource_type}')
        return value


def fixed(json_name: str, value: Any) -> Any:
    """Generates a type-friendly Fixed field."""
    return Fixed(json_name, value)


def rfc3339(json_name: str, omitempty: bool = False) -> Any:
    """Generates a type-friendly RFC3339 field."""
    return RFC3339Field(json_name, omitempty=omitempty)


def resource(resource_type: str) -> Any:
    """Generates a type-friendly Resource field."""
    return Resource(resource_type)
