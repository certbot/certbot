import os
from contextlib import contextmanager


def traverse_parents(path, include_current=False):
    if not include_current:
        path = os.path.dirname(path)

    previous = None
    while previous != path:
        yield path
        previous = path
        path = os.path.dirname(path)


@contextmanager
def monkeypatch(obj, attribute_name, new_value):
    """
    Like pytest's monkeypatch, but as a value manager.
    """
    old_value = getattr(obj, attribute_name)
    try:
        setattr(obj, attribute_name, new_value)
        yield
    finally:
        setattr(obj, attribute_name, old_value)
