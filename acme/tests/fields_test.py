"""Tests for acme.fields."""
import datetime
import unittest
import warnings

import josepy as jose
import pytz


class FixedTest(unittest.TestCase):
    """Tests for acme.fields.Fixed."""

    def setUp(self):
        from acme.fields import fixed
        self.field = fixed('name', 'x')

    def test_decode(self):
        self.assertEqual('x', self.field.decode('x'))

    def test_decode_bad(self):
        self.assertRaises(jose.DeserializationError, self.field.decode, 'y')

    def test_encode(self):
        self.assertEqual('x', self.field.encode('x'))

    def test_encode_override(self):
        self.assertEqual('y', self.field.encode('y'))


class RFC3339FieldTest(unittest.TestCase):
    """Tests for acme.fields.RFC3339Field."""

    def setUp(self):
        self.decoded = datetime.datetime(2015, 3, 27, tzinfo=pytz.utc)
        self.encoded = '2015-03-27T00:00:00Z'

    def test_default_encoder(self):
        from acme.fields import RFC3339Field
        self.assertEqual(
            self.encoded, RFC3339Field.default_encoder(self.decoded))

    def test_default_encoder_naive_fails(self):
        from acme.fields import RFC3339Field
        self.assertRaises(
            ValueError, RFC3339Field.default_encoder, datetime.datetime.now())

    def test_default_decoder(self):
        from acme.fields import RFC3339Field
        self.assertEqual(
            self.decoded, RFC3339Field.default_decoder(self.encoded))

    def test_default_decoder_raises_deserialization_error(self):
        from acme.fields import RFC3339Field
        self.assertRaises(
            jose.DeserializationError, RFC3339Field.default_decoder, '')


class ResourceTest(unittest.TestCase):
    """Tests for acme.fields.Resource."""

    def setUp(self):
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', '.*Resource', DeprecationWarning)
            from acme.fields import Resource
            self.field = Resource('x')

    def test_decode_good(self):
        self.assertEqual('x', self.field.decode('x'))

    def test_decode_wrong(self):
        self.assertRaises(jose.DeserializationError, self.field.decode, 'y')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
