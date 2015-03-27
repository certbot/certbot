"""JOSE utilities."""
import collections


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
    """Wrapper for M2Crypto.X509.* objects that supports __eq__.

    Wraps around:

      - :class:`M2Crypto.X509.X509`
      - :class:`M2Crypto.X509.Request`

    """
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __eq__(self, other):
        return self.as_der() == other.as_der()


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
