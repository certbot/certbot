'''
Decorators are not really values, however we need some wrappers to improve
docstrings and other things around decorators.
'''

from jedi.inference.base_value import ValueWrapper


class Decoratee(ValueWrapper):
    def __init__(self, wrapped_value, original_value):
        self._wrapped_value = wrapped_value
        self._original_value = original_value

    def py__doc__(self):
        return self._original_value.py__doc__()
