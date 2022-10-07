"""Module executing integration tests against Certbot with the RFC2136 DNS authenticator."""
from typing import Generator

import pytest

from certbot_integration_tests.rfc2136_tests.context import IntegrationTestsContext


@pytest.fixture(name="context")
def test_context(request: pytest.FixtureRequest) -> Generator[IntegrationTestsContext, None, None]:
    # pylint: disable=missing-function-docstring
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()
