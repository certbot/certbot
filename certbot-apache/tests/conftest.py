import sys


def pytest_ignore_collect(path, config):  # pragma: no cover
    # Do not run any test for certbot-apache on Windows, except obj_test which is safe
    # (to avoid pytest to fail because no test was found).
    if sys.platform == 'win32':
        return path.basename != 'dummy_test.py'
