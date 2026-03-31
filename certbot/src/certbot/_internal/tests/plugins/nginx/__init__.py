"""certbot-nginx tests"""
import pytest


# Make sure we're only running these tests if our nginx plugin dependencies are installed
pytest.importorskip("pyparsing")
