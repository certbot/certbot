import sys

def pytest_ignore_collect(path, config):
    # Do not run any test for certbot-apache on Windows.
    if sys.platform == 'win32':
        return True
