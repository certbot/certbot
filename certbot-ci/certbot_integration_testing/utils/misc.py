import subprocess
import os
import re
import unittest


def find_certbot_executable():
    try:
        return subprocess.check_output('which certbot',
                                       shell=True, universal_newlines=True).strip()
    except subprocess.CalledProcessError:
        try:
            return subprocess.check_output('where certbot',
                                           shell=True, universal_newlines=True).strip()
        except subprocess.CalledProcessError:
            pass

    raise ValueError('Error, could not find certbot executable')


def find_certbot_sources():
    script_path = os.path.realpath(__file__)
    current_dir = os.path.dirname(script_path)

    while '.git' not in os.listdir(current_dir) and current_dir != os.path.dirname(current_dir):
        current_dir = os.path.dirname(current_dir)

    dirs = os.listdir(current_dir)
    if '.git' not in dirs:
        raise ValueError('Error, could not find certbot sources root directory')

    return [os.path.join(current_dir, dir) for dir in dirs
            if (dir == 'acme' or (re.match('^certbot.*$', dir)
                                  and dir not in ['certbot-ci', 'certbot.egg-info']))
            and os.path.isdir(dir)]


def skip_on_pebble(reason):
    """
    Decorator to skip a test against Pebble instances.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return unittest.skipIf('pebble' in os.environ.get('CERTBOT_INTEGRATION'), reason)(func)
    return wrapper


def skip_on_pebble_strict(reason):
    """
    Decorator to skip a test against Pebble instances with strict mode enabled.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return unittest.skipIf(os.environ.get('CERTBOT_INTEGRATION')
                               == 'pebble-strict', reason)(func)
    return wrapper
