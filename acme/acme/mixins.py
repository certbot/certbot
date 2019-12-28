from josepy import JSONObjectWithFields

from acme.magic_typing import TYPE_CHECKING  # pylint: disable=unused-import, no-name-in-module

if TYPE_CHECKING:
    _Base = JSONObjectWithFields
else:
    _Base = object


class VersionedLEACMEMixin(object):
    @property
    def le_auto_version(self):
        return getattr(self, '_le_auto_version', 1)

    @le_auto_version.setter
    def le_auto_version(self, version):
        # We need to use object.__setattr__ to not depend on the specific implementation of
        # __setattr__  in current class (eg. jose.TypedJSONObjectWithFields raises AttributeError
        # for any attempt to set an attribute to make objects immutable).
        object.__setattr__(self, '_le_auto_version', version)

    def __setattr__(self, key, value):
        if key == 'le_auto_version':
            # Needed to allow @property to operate properly. See comment above.
            object.__setattr__(self, key, value)
        else:
            super(VersionedLEACMEMixin, self).__setattr__(key, value)


class ResourceMixin(VersionedLEACMEMixin, _Base):
    def to_partial_json(self):
        if hasattr(super(ResourceMixin, self), 'to_partial_json'):
            jobj = super(ResourceMixin, self).to_partial_json()
            if self.le_auto_version == 2:
                jobj.pop('resource', None)
            return jobj

        raise AttributeError('This class does not implement method to_partial_json().')


class TypeMixin(VersionedLEACMEMixin, _Base):
    def to_partial_json(self):
        if hasattr(super(TypeMixin, self), 'to_partial_json'):
            jobj = super(TypeMixin, self).to_partial_json()
            if self.le_auto_version == 2:
                jobj.pop('type', None)
            return jobj

        raise AttributeError('This class does not implement method to_partial_json().')
