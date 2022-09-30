"""ACME JSON fields."""
import datetime
import logging
import sys
from types import ModuleType
from typing import Any
from typing import cast
from typing import List
import warnings

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
    """Resource MITM field.

    .. deprecated: 1.30.0

    """

    def __init__(self, resource_type: str, *args: Any, **kwargs: Any) -> None:
        self.resource_type = resource_type
        kwargs['default'] = resource_type
        super().__init__('resource', *args, **kwargs)

    def decode(self, value: Any) -> Any:
        if value != self.resource_type:
            raise jose.DeserializationError(
                'Wrong resource type: {0} instead of {1}'.format(
                    value, self.resource_type))
        return value


def fixed(json_name: str, value: Any) -> Any:
    """Generates a type-friendly Fixed field."""
    return Fixed(json_name, value)


def rfc3339(json_name: str, omitempty: bool = False) -> Any:
    """Generates a type-friendly RFC3339 field."""
    return RFC3339Field(json_name, omitempty=omitempty)


def resource(resource_type: str) -> Any:
    """Generates a type-friendly Resource field.

    .. deprecated: 1.30.0

    """
    return Resource(resource_type)


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _FieldsDeprecationModule: # pragma: no cover
    """
    Internal class delegating to a module, and displaying warnings when
    module attributes deprecated in acme.fields are accessed.
    """
    def __init__(self, module: ModuleType) -> None:
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> None:
        if attr in ('Resource', 'resource'):
            warnings.warn('{0} attribute in acme.fields module is deprecated '
                          'and will be removed soon.'.format(attr),
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> None:
        delattr(self._module, attr)

    def __dir__(self) -> List[str]:
        return ['_module'] + dir(self._module)


sys.modules[__name__] = cast(ModuleType, _FieldsDeprecationModule(sys.modules[__name__]))
