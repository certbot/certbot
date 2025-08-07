"""ACME JSON fields."""
import datetime
import logging
from typing import Any

import josepy as jose
import pyrfc3339

logger = logging.getLogger(__name__)


class Fixed(jose.Field):
    """Fixed field."""

    def __init__(self, json_name: str, value: Any) -> None:
        self.value = value
        super().__init__(
            json_name=json_name, default=value, omitempty=False)

    def decode(self, value: Any) -> Any:
        if value != self.value:
            raise jose.DeserializationError(f'Expected {self.value!r}')
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
    (e.g. ``datetime.datetime.now(datetime.timezone.utc)``).

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


def fixed(json_name: str, value: Any) -> Any:
    """Generates a type-friendly Fixed field."""
    return Fixed(json_name, value)


def rfc3339(json_name: str, omitempty: bool = False) -> Any:
    """Generates a type-friendly RFC3339 field."""
    return RFC3339Field(json_name, omitempty=omitempty)
