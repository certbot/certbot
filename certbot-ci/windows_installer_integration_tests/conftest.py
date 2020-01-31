"""
General conftest for pytest execution of all integration tests lying
in the window_installer_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""
from __future__ import print_function
import os

import pytest

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def pytest_addoption(parser):
    """
    Standard pytest hook to add options to the pytest parser.
    :param parser: current pytest parser that will be used on the CLI
    """
    parser.addoption('--installer-path',
                     default=os.path.join(ROOT_PATH, 'windows-installer', 'build',
                                          'nsis', 'certbot-beta-installer-win32.exe'),
                     help='set the path of the windows installer to use, default to '
                          'CERTBOT_ROOT_PATH\\windows-installer\\build\\nsis\\certbot-beta-installer-win32.exe')
    parser.addoption('--confirm', action='store_true',
                     help='if set, this test will not ask for user confirmation before running')


def pytest_configure(config):
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param config: the current pytest configuration
    """
    if not config.option.confirm:
        capture_manager = config.pluginmanager.getplugin('capturemanager')
        try:
            capture_manager.suspendcapture(in_=True)

            print('++ WARNING ++')
            print('-------------')
            print('This integration test will install Certbot on your machine.')
            print('At the end of the test you will need to manually uninstall it.')
            print('-------------')

            input('Please press ENTER to continue, or CTRL+C to cancel.')
        finally:
            capture_manager.resumecapture()
