"""
General conftest for pytest execution of all integration tests lying
in the window_installer_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""
from __future__ import print_function
import os

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
