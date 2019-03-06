import pytest

# Custom assertions defined in following package needs to be registered to be properly
# displayed in a pytest report when they are failing.
pytest.register_assert_rewrite('certbot_integration_tests.certbot_tests.assertions')