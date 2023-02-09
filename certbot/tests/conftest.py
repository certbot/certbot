import pytest

from certbot._internal import cli


@pytest.fixture(autouse=True)
def reset_cli_global():
    cli.set_by_cli.detector = None
