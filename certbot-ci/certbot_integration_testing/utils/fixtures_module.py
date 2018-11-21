import pytest


@pytest.fixture(scope='module')
def common_no_force_renew(certbot_test_no_force_renew):
    def func(args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_test_no_force_renew(command)

    return func


@pytest.fixture(scope='module')
def common(common_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return common_no_force_renew(command)

    return func
