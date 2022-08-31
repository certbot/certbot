"""Useful mixins for Challenge and Resource objects"""
from typing import Any
from typing import Dict


class TypeMixin:
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
        jobj.pop(uncompliant_field, None)
        return jobj

    raise AttributeError(f'Method {jobj_method}() is not implemented.')  # pragma: no cover
