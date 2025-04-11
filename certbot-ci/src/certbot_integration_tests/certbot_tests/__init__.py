# pylint: disable=missing-module-docstring
import pytest

# Custom assertions defined in the following package need to be registered to be properly
# displayed in a pytest report when they are failing.
pytest.register_assert_rewrite('certbot_integration_tests.certbot_tests.assertions')
