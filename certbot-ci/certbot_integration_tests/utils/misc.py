"""
Misc module contains stateless functions that could be used during pytest execution,
or outside during setup/teardown of the integration tests environment.
"""
import os
import time
import contextlib

import requests


def check_until_timeout(url):
    """
    Wait and block until given url responds with status 200, or raise an exception
    after 150 attempts.
    :param str url: the URL to test
    :raise ValueError: exception raised after 150 unsuccessful attempts to reach the URL
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for _ in range(0, 150):
        time.sleep(1)
        try:
            if requests.get(url, verify=False).status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))


@contextlib.contextmanager
def execute_in_given_cwd(cwd):
    """
    Context manager that will execute any command in the given cwd after entering context,
    and restore current cwd when context is destroyed.
    :param str cwd: the path to use as the temporary current workspace for python execution
    """
    current_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        yield
    finally:
        os.chdir(current_cwd)
