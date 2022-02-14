# type: ignore
"""
General conftest for pytest execution of all integration tests lying
in the window_installer_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""

import os

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def pytest_addoption(parser):
    """
    Standard pytest hook to add options to the pytest parser.
    :param parser: current pytest parser that will be used on the CLI
    """
    parser.addoption('--installer-path',
                     default=os.path.join(ROOT_PATH, 'windows-installer', 'build',
                                          'nsis', 'certbot-beta-installer-win64.exe'),
                     help='set the path of the windows installer to use, default to '
                          'CERTBOT_ROOT_PATH\\windows-installer\\build\\nsis\\certbot-beta-installer-win64.exe')  # pylint: disable=line-too-long
    parser.addoption('--allow-persistent-changes', action='store_true',
                     help='needs to be set, and confirm that the test will make persistent changes on this machine')  # pylint: disable=line-too-long


def pytest_configure(config):
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param config: the current pytest configuration
    """
    if not config.option.allow_persistent_changes:
        raise RuntimeError('This integration test would install Certbot on your machine. '
                           'Please run it again with the `--allow-persistent-changes` '
                           'flag set to acknowledge.')
