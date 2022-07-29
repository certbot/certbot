"""Useful mixins for Challenge and Resource objects"""
from typing import Any
from typing import Dict
import warnings

warnings.warn(f'The module {__name__} is deprecated and will be removed in a future release',
              DeprecationWarning)


class VersionedLEACMEMixin:
    """This mixin stores the version of Let's Encrypt's endpoint being used."""
    @property
    def le_acme_version(self) -> int:
        """Define the version of ACME protocol to use"""
        return getattr(self, '_le_acme_version', 1)

    @le_acme_version.setter
    def le_acme_version(self, version: int) -> None:
        # We need to use object.__setattr__ to not depend on the specific implementation of
        # __setattr__  in current class (eg. jose.TypedJSONObjectWithFields raises AttributeError
        # for any attempt to set an attribute to make objects immutable).
        object.__setattr__(self, '_le_acme_version', version)

    def __setattr__(self, key: str, value: Any) -> None:
        if key == 'le_acme_version':
            # Required for @property to operate properly. See comment above.
            object.__setattr__(self, key, value)
        else:
            super().__setattr__(key, value)  # pragma: no cover


class ResourceMixin(VersionedLEACMEMixin):
    """
    This mixin generates a RFC8555 compliant JWS payload
    by removing the `resource` field if needed (eg. ACME v2 protocol).
    """
    def to_partial_json(self) -> Dict[str, Any]:
        """See josepy.JSONDeserializable.to_partial_json()"""
        return _safe_jobj_compliance(super(),
                                     'to_partial_json', 'resource')

    def fields_to_partial_json(self) -> Dict[str, Any]:
        """See josepy.JSONObjectWithFields.fields_to_partial_json()"""
        return _safe_jobj_compliance(super(),
                                     'fields_to_partial_json', 'resource')


class TypeMixin(VersionedLEACMEMixin):
    """
    This mixin allows generation of a RFC8555 compliant JWS payload
    by removing the `type` field if needed (eg. ACME v2 protocol).
    """
    def to_partial_json(self) -> Dict[str, Any]:
        """See josepy.JSONDeserializable.to_partial_json()"""
        return _safe_jobj_compliance(super(),
                                     'to_partial_json', 'type')

    def fields_to_partial_json(self) -> Dict[str, Any]:
        """See josepy.JSONObjectWithFields.fields_to_partial_json()"""
        return _safe_jobj_compliance(super(),
                                     'fields_to_partial_json', 'type')


def _safe_jobj_compliance(instance: Any, jobj_method: str,
                          uncompliant_field: str) -> Dict[str, Any]:
    if hasattr(instance, jobj_method):
        jobj: Dict[str, Any] = getattr(instance, jobj_method)()
        if instance.le_acme_version == 2:
            jobj.pop(uncompliant_field, None)
        return jobj

    raise AttributeError(f'Method {jobj_method}() is not implemented.')  # pragma: no cover
