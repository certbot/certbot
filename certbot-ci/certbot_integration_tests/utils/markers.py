from unittest import skipIf
import os


def skip_on_pebble(reason):
    """
    Decorator to skip a test against Pebble instances.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return skipIf('pebble' in os.environ.get('CERTBOT_INTEGRATION'), reason)(func)
    return wrapper


def skip_on_pebble_strict(reason):
    """
    Decorator to skip a test against Pebble instances with strict mode enabled.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return skipIf(os.environ.get('CERTBOT_INTEGRATION') == 'pebble-strict', reason)(func)
    return wrapper


def skip_on_boulder_v1(reason):
    """
    Decorator to skip a test against Pebble instances with strict mode enabled.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return skipIf(os.environ.get('CERTBOT_INTEGRATION') == 'boulder-v1', reason)(func)
    return wrapper
