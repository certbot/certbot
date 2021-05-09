"""Tests for certbot.services."""
import unittest
from unittest.mock import MagicMock

from certbot import services


class RelevantValuesTest(unittest.TestCase):
    """Tests for certbot.services.

    Please note that order of tests is important, because it will also test that
    services are globally available from one test to another one.
    """
    @classmethod
    def setUpClass(cls):
        # Isolate global services for the time of this TestCase
        services._services = services._Services()

    @classmethod
    def tearDownClass(cls):
        services._services = services._Services()

    def test_config_service(self):
        self.assertIsNone(services.get_config())

        config = MagicMock()

        services.set_config(config)

        self.assertEqual(id(services.get_config()), id(config))
        self.assertIsNone(services.get_display())
        self.assertIsNone(services.get_reporter())

    def test_display_service(self):
        self.assertIsNone(services.get_display())

        config = MagicMock()

        services.set_display(config)

        self.assertEqual(id(services.get_display()), id(config))
        self.assertIsNotNone(services.get_config())  # Set since test_config_service has been run
        self.assertIsNone(services.get_reporter())

    def test_reporter_service(self):
        self.assertIsNone(services.get_reporter())

        config = MagicMock()

        services.set_reporter(config)

        self.assertEqual(id(services.get_reporter()), id(config))
        self.assertIsNotNone(services.get_config())  # Set since test_config_service has been run
        self.assertIsNotNone(services.get_display())  # Set since test_display_service has been run
