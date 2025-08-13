from unittest import mock

import pytest

@pytest.fixture(autouse=True)
def mock_getfqdn():
    with mock.patch("socket.getfqdn", return_value="server_name") as mocked:
        yield mocked

@pytest.fixture(autouse=True)
def mock_sleep():
    with mock.patch("time.sleep") as mocked:
        yield mocked
