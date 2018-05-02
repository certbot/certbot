import sys

class TypingClass(object):
    def __getattr__(self, name):
        return None

try:
    import typing
    sys.modules[__name__] = typing
except ImportError:
    sys.modules[__name__] = TypingClass()
