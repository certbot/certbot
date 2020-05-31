from abc import ABCMeta, abstractmethod
from typing import Callable, Dict, Iterable, List, Tuple, Union, cast

__all__ = ["Filter", "Never", "Always", "Condition", "FilterOrBool"]


class Filter(metaclass=ABCMeta):
    """
    Base class for any filter to activate/deactivate a feature, depending on a
    condition.

    The return value of ``__call__`` will tell if the feature should be active.
    """

    @abstractmethod
    def __call__(self) -> bool:
        """
        The actual call to evaluate the filter.
        """
        return True

    def __and__(self, other: "Filter") -> "Filter":
        """
        Chaining of filters using the & operator.
        """
        return _and_cache[self, other]

    def __or__(self, other: "Filter") -> "Filter":
        """
        Chaining of filters using the | operator.
        """
        return _or_cache[self, other]

    def __invert__(self) -> "Filter":
        """
        Inverting of filters using the ~ operator.
        """
        return _invert_cache[self]

    def __bool__(self) -> None:
        """
        By purpose, we don't allow bool(...) operations directly on a filter,
        because the meaning is ambiguous.

        Executing a filter has to be done always by calling it. Providing
        defaults for `None` values should be done through an `is None` check
        instead of for instance ``filter1 or Always()``.
        """
        raise ValueError(
            "The truth value of a Filter is ambiguous. "
            "Instead, call it as a function."
        )


class _AndCache(Dict[Tuple[Filter, Filter], "_AndList"]):
    """
    Cache for And operation between filters.
    (Filter classes are stateless, so we can reuse them.)

    Note: This could be a memory leak if we keep creating filters at runtime.
          If that is True, the filters should be weakreffed (not the tuple of
          filters), and tuples should be removed when one of these filters is
          removed. In practise however, there is a finite amount of filters.
    """

    def __missing__(self, filters: Tuple[Filter, Filter]) -> Filter:
        a, b = filters
        assert isinstance(b, Filter), "Expecting filter, got %r" % b

        if isinstance(b, Always) or isinstance(a, Never):
            return a
        elif isinstance(b, Never) or isinstance(a, Always):
            return b

        result = _AndList(filters)
        self[filters] = result
        return result


class _OrCache(Dict[Tuple[Filter, Filter], "_OrList"]):
    """ Cache for Or operation between filters. """

    def __missing__(self, filters: Tuple[Filter, Filter]) -> Filter:
        a, b = filters
        assert isinstance(b, Filter), "Expecting filter, got %r" % b

        if isinstance(b, Always) or isinstance(a, Never):
            return b
        elif isinstance(b, Never) or isinstance(a, Always):
            return a

        result = _OrList(filters)
        self[filters] = result
        return result


class _InvertCache(Dict[Filter, "_Invert"]):
    """ Cache for inversion operator. """

    def __missing__(self, filter: Filter) -> Filter:
        result = _Invert(filter)
        self[filter] = result
        return result


_and_cache = _AndCache()
_or_cache = _OrCache()
_invert_cache = _InvertCache()


class _AndList(Filter):
    """
    Result of &-operation between several filters.
    """

    def __init__(self, filters: Iterable[Filter]) -> None:
        self.filters: List[Filter] = []

        for f in filters:
            if isinstance(f, _AndList):  # Turn nested _AndLists into one.
                self.filters.extend(cast(_AndList, f).filters)
            else:
                self.filters.append(f)

    def __call__(self) -> bool:
        return all(f() for f in self.filters)

    def __repr__(self) -> str:
        return "&".join(repr(f) for f in self.filters)


class _OrList(Filter):
    """
    Result of |-operation between several filters.
    """

    def __init__(self, filters: Iterable[Filter]) -> None:
        self.filters: List[Filter] = []

        for f in filters:
            if isinstance(f, _OrList):  # Turn nested _OrLists into one.
                self.filters.extend(cast(_OrList, f).filters)
            else:
                self.filters.append(f)

    def __call__(self) -> bool:
        return any(f() for f in self.filters)

    def __repr__(self) -> str:
        return "|".join(repr(f) for f in self.filters)


class _Invert(Filter):
    """
    Negation of another filter.
    """

    def __init__(self, filter: Filter) -> None:
        self.filter = filter

    def __call__(self) -> bool:
        return not self.filter()

    def __repr__(self) -> str:
        return "~%r" % self.filter


class Always(Filter):
    """
    Always enable feature.
    """

    def __call__(self) -> bool:
        return True

    def __invert__(self) -> "Never":
        return Never()


class Never(Filter):
    """
    Never enable feature.
    """

    def __call__(self) -> bool:
        return False

    def __invert__(self) -> Always:
        return Always()


class Condition(Filter):
    """
    Turn any callable into a Filter. The callable is supposed to not take any
    arguments.

    This can be used as a decorator::

        @Condition
        def feature_is_active():  # `feature_is_active` becomes a Filter.
            return True

    :param func: Callable which takes no inputs and returns a boolean.
    """

    def __init__(self, func: Callable[[], bool]):
        self.func = func

    def __call__(self) -> bool:
        return self.func()

    def __repr__(self) -> str:
        return "Condition(%r)" % self.func


# Often used as type annotation.
FilterOrBool = Union[Filter, bool]
