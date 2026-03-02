from unittest import mock

import pytest

# This avoids a bug on mac where getfqdn errors after a long timeout.
# See https://bugs.python.org/issue35164
# and discussion at https://github.com/certbot/certbot/pull/10408
@pytest.fixture(autouse=True)
def mock_getfqdn():
    with mock.patch("socket.getfqdn", return_value="server_name") as mocked:
        yield mocked

@pytest.fixture(autouse=True)
def mock_sleep():
    with mock.patch("time.sleep") as mocked:
        yield mocked
