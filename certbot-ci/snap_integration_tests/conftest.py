"""
General conftest for pytest execution of all integration tests lying
in the snap_installer_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""
import glob
import os


def pytest_addoption(parser):
    """
    Standard pytest hook to add options to the pytest parser.
    :param parser: current pytest parser that will be used on the CLI
    """
    parser.addoption('--snap-folder', required=True,
                     help='set the folder path where snaps to test are located')
    parser.addoption('--snap-arch', default='amd64',
                    help='set the architecture do test (default: amd64)')
    parser.addoption('--allow-persistent-changes', action='store_true',
                     help='needs to be set, and confirm that the test will make persistent changes on this machine')


def pytest_configure(config):
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param config: the current pytest configuration
    """
    if not config.option.allow_persistent_changes:
        raise RuntimeError('This integration test would install the Certbot snap on your machine. '
                           'Please run it again with the `--allow-persistent-changes` flag set to acknowledge.')


def pytest_generate_tests(metafunc):
    """
    Generate (multiple) parametrized calls to a test function.
    """
    if "dns_snap_path" in metafunc.fixturenames:
        snap_arch = metafunc.config.getoption('snap_arch')
        snap_folder = metafunc.config.getoption('snap_folder')
        snap_dns_path_list = glob.glob(os.path.join(snap_folder, 
                                                    'certbot-dns-*_{0}.snap'.format(snap_arch)))
        metafunc.parametrize("dns_snap_path", snap_dns_path_list)
