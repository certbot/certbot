"""ACME interfaces.

Separation between :class:`IJSONSerializable` and :class:`IJSONDeserializable`
is necessary because we want to use ``cls.from_valid_json``
classmethod on class and ``cls().to_json()`` on object, i.e. class
instance. ``cls.to_json()`` doesn't make much sense. Therefore a class
definition that requires both must call
``zope.interface.implements(IJSONSerializable)`` and
``zope.interface.classImplements(IJSONDeSerializable)`` (note the
difference btween `implements` and `classImplements`) and
:class:`letsencrypt.acme.util.ACMEObject` definition is an example.

"""
import zope.interface

# pylint: disable=no-self-argument,no-method-argument,no-init,inherit-non-class
# pylint: disable=too-few-public-methods


class IJSONSerializable(zope.interface.Interface):
    # pylint: disable=too-few-public-methods
    """JSON serializable object."""

    def to_json():
        """Prepare JSON serializable object.

        Note, however, that this method might return other
        :class:`letsencrypt.acme.interfaces.IJSONSerializable`
        objects that haven't been serialized yet, which is fine as
        long as :func:`letsencrypt.acme.util.dump_ijsonserializable`
        is used. For example::

          class Foo(object):
              zope.interface.implements(IJSONSerializable)

              def to_json(self):
                  return 'foo'

          class Bar(object):
              zope.interface.implements(IJSONSerializable)

              def to_json(self):
                  return [Foo(), Foo()]

          bar = Bar()
          assert isinstance(bar.to_json()[0], Foo)
          assert isinstance(bar.to_json()[1], Foo)
          assert json.dumps(
              bar, default=dump_ijsonserializable) == ['foo', 'foo']

        :returns: JSON object ready to be serialized.

        """

class IJSONDeserializable(zope.interface.Interface):
    """JSON deserializable class."""

    def from_valid_json(jobj):
        """Deserialize valid JSON object.

        :param jobj: JSON object validated against JSON schema (found in
            schemata/ directory).

        :raises letsencrypt.acme.errors.ValidationError: It might be the
            case that ``jobj`` validates against schema, but still is not
            valid (e.g. unparseable X509 certificate, or wrong padding in
            JOSE base64 encoded string).

        """
