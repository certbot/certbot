"""certbot-apache tests"""

import pytest


# Make sure we're only running these tests if our apache plugin dependencies are installed
pytest.importorskip("augeas")
