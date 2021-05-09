"""Tests for certbot.services."""
import unittest
from unittest.mock import MagicMock

from certbot import services


class RelevantValuesTest(unittest.TestCase):
    """Tests for certbot.services."""
    def setUp(self):
        # Isolate global services for each test
        services._services = services._Services()

    def tearDown(self):
        services._services = services._Services()

    def test_config_service(self):
        self.assertRaises(ValueError, services.get_config)

        config = MagicMock()

        services.set_config(config)

        self.assertEqual(id(services.get_config()), id(config))

    def test_display_service(self):
        self.assertRaises(ValueError, services.get_display)

        config = MagicMock()

        services.set_display(config)

        self.assertEqual(id(services.get_display()), id(config))

    def test_reporter_service(self):
        self.assertRaises(ValueError, services.get_reporter)

        config = MagicMock()

        services.set_reporter(config)

        self.assertEqual(id(services.get_reporter()), id(config))
