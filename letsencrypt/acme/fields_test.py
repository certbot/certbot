"""Tests for letsencrypt.acme.fields."""
import datetime
import unittest

import pytz

from letsencrypt.acme import jose


class RFC3339FieldTest(unittest.TestCase):
    """Tests for letsencrypt.acme.fields.RFC3339Field."""

    def setUp(self):
        self.decoded = datetime.datetime(2015, 3, 27, tzinfo=pytz.utc)
        self.encoded = '2015-03-27T00:00:00Z'

    def test_default_encoder(self):
        from letsencrypt.acme.fields import RFC3339Field
        self.assertEqual(
            self.encoded, RFC3339Field.default_encoder(self.decoded))

    def test_default_encoder_naive_fails(self):
        from letsencrypt.acme.fields import RFC3339Field
        self.assertRaises(
            ValueError, RFC3339Field.default_encoder, datetime.datetime.now())

    def test_default_decoder(self):
        from letsencrypt.acme.fields import RFC3339Field
        self.assertEqual(
            self.decoded, RFC3339Field.default_decoder(self.encoded))

    def test_default_decoder_raises_deserialization_error(self):
        from letsencrypt.acme.fields import RFC3339Field
        self.assertRaises(
            jose.DeserializationError, RFC3339Field.default_decoder, '')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
