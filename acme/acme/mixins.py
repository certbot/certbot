"""Useful mixins for Challenge and Resource objects"""


class VersionedLEACMEMixin(object):
    """This mixin allows to store the current ACME version as a property"""
    @property
    def le_acme_version(self):
        """Define the version of ACME protocol to use"""
        return getattr(self, '_le_acme_version', 1)

    @le_acme_version.setter
    def le_acme_version(self, version):
        # We need to use object.__setattr__ to not depend on the specific implementation of
        # __setattr__  in current class (eg. jose.TypedJSONObjectWithFields raises AttributeError
        # for any attempt to set an attribute to make objects immutable).
        object.__setattr__(self, '_le_acme_version', version)

    def __setattr__(self, key, value):
        if key == 'le_acme_version':
            # Required for @property to operate properly. See comment above.
            object.__setattr__(self, key, value)
        else:
            super(VersionedLEACMEMixin, self).__setattr__(key, value)  # pragma: no cover


class ResourceMixin(VersionedLEACMEMixin):
    """
    This mixin allows to generate a RFC8555 compliant JWS payload
    by removing the `resource` field if needed (eg. ACME v2 protocol).
    """
    def to_partial_json(self):
        """See josepy.JSONDeserializable.to_partial_json()"""
        if hasattr(super(ResourceMixin, self), 'to_partial_json'):
            jobj = super(ResourceMixin, self).to_partial_json()  # type: ignore
            if self.le_acme_version == 2:
                jobj.pop('resource', None)
            return jobj

        raise AttributeError('Method to_partial_json() is not implemented.')  # pragma: no cover


class TypeMixin(VersionedLEACMEMixin):
    """
    This mixin allows to generate a RFC8555 compliant JWS payload
    by removing the `type` field if needed (eg. ACME v2 protocol).
    """
    def to_partial_json(self):
        """See josepy.JSONDeserializable.to_partial_json()"""
        if hasattr(super(TypeMixin, self), 'to_partial_json'):
            jobj = super(TypeMixin, self).to_partial_json()  # type: ignore
            if self.le_acme_version == 2:
                jobj.pop('type', None)
            return jobj

        raise AttributeError('Method to_partial_json() is not implemented.')  # pragma: no cover
