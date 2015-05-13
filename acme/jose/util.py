"""JOSE utilities."""
import collections

from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL


class abstractclassmethod(classmethod):
    # pylint: disable=invalid-name,too-few-public-methods
    """Descriptor for an abstract classmethod.

    It augments the :mod:`abc` framework with an abstract
    classmethod. This is implemented as :class:`abc.abstractclassmethod`
    in the standard Python library starting with version 3.2.

    This particular implementation, allegedly based on Python 3.3 source
    code, is stolen from
    http://stackoverflow.com/questions/11217878/python-2-7-combine-abc-abstractmethod-and-classmethod.

    """
    __isabstractmethod__ = True

    def __init__(self, target):
        target.__isabstractmethod__ = True
        super(abstractclassmethod, self).__init__(target)


class ComparableX509(object):  # pylint: disable=too-few-public-methods
    """Wrapper for OpenSSL.crypto.X509** objects that supports __eq__.

    Wraps around:

      - :class:`OpenSSL.crypto.X509`
      - :class:`OpenSSL.crypto.X509Req`

    """
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __eq__(self, other):
        filetype = OpenSSL.crypto.FILETYPE_ASN1
        def as_der(obj):
            # pylint: disable=missing-docstring,protected-access
            if isinstance(obj, type(self)):
                obj = obj._wrapped
            if isinstance(obj, OpenSSL.crypto.X509):
                func = OpenSSL.crypto.dump_certificate
            elif isinstance(obj, OpenSSL.crypto.X509Req):
                func = OpenSSL.crypto.dump_certificate_request
            else:
                raise TypeError(
                    "Equality for {0} not provided".format(obj.__class__))
            return func(filetype, obj)
        return as_der(self) == as_der(other)

    def __repr__(self):
        return '<{0}({1!r})>'.format(self.__class__.__name__, self._wrapped)


class ComparableRSAKey(object):  # pylint: disable=too-few-public-methods
    """Wrapper for `cryptography` RSA keys.

    Wraps around:
    - `cryptography.hazmat.primitives.assymetric.RSAPrivateKey`
    - `cryptography.hazmat.primitives.assymetric.RSAPublicKey`

    """
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __eq__(self, other):
        # pylint: disable=protected-access
        if (not isinstance(other, self.__class__) or
                self._wrapped.__class__ is not other._wrapped.__class__):
            return False
        # RSA*KeyWithSerialization requires cryptography>=0.8
        if isinstance(self._wrapped, rsa.RSAPrivateKeyWithSerialization):
            return self.private_numbers() == other.private_numbers()
        elif isinstance(self._wrapped, rsa.RSAPublicKeyWithSerialization):
            return self.public_numbers() == other.public_numbers()
        else:
            return False  # we shouldn't reach here...


    def __hash__(self):
        # public_numbers() hasn't got stable hash!
        if isinstance(self._wrapped, rsa.RSAPrivateKeyWithSerialization):
            priv = self.private_numbers()
            pub = priv.public_numbers
            return hash((type(self), priv.p, priv.q, priv.dmp1,
                         priv.dmq1, priv.iqmp, pub.n, pub.e))
        elif isinstance(self._wrapped, rsa.RSAPublicKeyWithSerialization):
            pub = self.public_numbers()
            return hash((type(self), pub.n, pub.e))

    def __repr__(self):
        return '<{0}({1!r})>'.format(self.__class__.__name__, self._wrapped)

    def public_key(self):
        """Get wrapped public key."""
        return type(self)(self._wrapped.public_key())


class ImmutableMap(collections.Mapping, collections.Hashable):
    # pylint: disable=too-few-public-methods
    """Immutable key to value mapping with attribute access."""

    __slots__ = ()
    """Must be overriden in subclasses."""

    def __init__(self, **kwargs):
        if set(kwargs) != set(self.__slots__):
            raise TypeError(
                '__init__() takes exactly the following arguments: {0} '
                '({1} given)'.format(', '.join(self.__slots__),
                                     ', '.join(kwargs) if kwargs else 'none'))
        for slot in self.__slots__:
            object.__setattr__(self, slot, kwargs.pop(slot))

    def update(self, **kwargs):
        """Return updated map."""
        items = dict(self)
        items.update(kwargs)
        return type(self)(**items)  # pylint: disable=star-args

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __iter__(self):
        return iter(self.__slots__)

    def __len__(self):
        return len(self.__slots__)

    def __hash__(self):
        return hash(tuple(getattr(self, slot) for slot in self.__slots__))

    def __setattr__(self, name, value):
        raise AttributeError("can't set attribute")

    def __repr__(self):
        return '{0}({1})'.format(self.__class__.__name__, ', '.join(
            '{0}={1!r}'.format(key, value) for key, value in self.iteritems()))


class frozendict(collections.Mapping, collections.Hashable):
    # pylint: disable=invalid-name,too-few-public-methods
    """Frozen dictionary."""
    __slots__ = ('_items', '_keys')

    def __init__(self, *args, **kwargs):
        if kwargs and not args:
            items = dict(kwargs)
        elif len(args) == 1 and isinstance(args[0], collections.Mapping):
            items = args[0]
        else:
            raise TypeError()
        # TODO: support generators/iterators

        object.__setattr__(self, '_items', items)
        object.__setattr__(self, '_keys', tuple(sorted(items.iterkeys())))

    def __getitem__(self, key):
        return self._items[key]

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._items)

    def __hash__(self):
        return hash(tuple((key, value) for key, value in self.items()))

    def __getattr__(self, name):
        try:
            return self._items[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        raise AttributeError("can't set attribute")

    def __repr__(self):
        return 'frozendict({0})'.format(', '.join(
            '{0}={1!r}'.format(key, value) for key, value in self.iteritems()))
