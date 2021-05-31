import sys

def pytest_ignore_collect(path, config):  # pragma: no cover
    # Do not run any test for certbot-apache on Windows.
    if sys.platform == 'win32':
        return True
