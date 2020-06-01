"""Tests for josepy.json_util."""
import itertools
import unittest

import mock
import six

from josepy import errors, interfaces, test_util, util

CERT = test_util.load_comparable_cert('cert.pem')
CSR = test_util.load_comparable_csr('csr.pem')


class FieldTest(unittest.TestCase):
    """Tests for josepy.json_util.Field."""

    def test_no_omit_boolean(self):
        from josepy.json_util import Field
        for default, omitempty, value in itertools.product(
                [True, False], [True, False], [True, False]):
            self.assertFalse(
                Field("foo", default=default, omitempty=omitempty).omit(value))

    def test_descriptors(self):
        mock_value = mock.MagicMock()

        # pylint: disable=missing-docstring

        def decoder(unused_value):
            return 'd'

        def encoder(unused_value):
            return 'e'

        from josepy.json_util import Field
        field = Field('foo')

        field = field.encoder(encoder)
        self.assertEqual('e', field.encode(mock_value))

        field = field.decoder(decoder)
        self.assertEqual('e', field.encode(mock_value))
        self.assertEqual('d', field.decode(mock_value))

    def test_default_encoder_is_partial(self):
        class MockField(interfaces.JSONDeSerializable):
            # pylint: disable=missing-docstring
            def to_partial_json(self):
                return 'foo'  # pragma: no cover

            @classmethod
            def from_json(cls, jobj):
                pass  # pragma: no cover
        mock_field = MockField()

        from josepy.json_util import Field
        self.assertTrue(Field.default_encoder(mock_field) is mock_field)
        # in particular...
        self.assertNotEqual('foo', Field.default_encoder(mock_field))

    def test_default_encoder_passthrough(self):
        mock_value = mock.MagicMock()
        from josepy.json_util import Field
        self.assertTrue(Field.default_encoder(mock_value) is mock_value)

    def test_default_decoder_list_to_tuple(self):
        from josepy.json_util import Field
        self.assertEqual((1, 2, 3), Field.default_decoder([1, 2, 3]))

    def test_default_decoder_dict_to_frozendict(self):
        from josepy.json_util import Field
        obj = Field.default_decoder({'x': 2})
        self.assertTrue(isinstance(obj, util.frozendict))
        self.assertEqual(obj, util.frozendict(x=2))

    def test_default_decoder_passthrough(self):
        mock_value = mock.MagicMock()
        from josepy.json_util import Field
        self.assertTrue(Field.default_decoder(mock_value) is mock_value)


class JSONObjectWithFieldsMetaTest(unittest.TestCase):
    """Tests for josepy.json_util.JSONObjectWithFieldsMeta."""

    def setUp(self):
        from josepy.json_util import Field
        from josepy.json_util import JSONObjectWithFieldsMeta
        self.field = Field('Baz')
        self.field2 = Field('Baz2')
        # pylint: disable=invalid-name,missing-docstring,too-few-public-methods
        # pylint: disable=blacklisted-name

        @six.add_metaclass(JSONObjectWithFieldsMeta)
        class A(object):
            __slots__ = ('bar',)
            baz = self.field

        class B(A):
            pass

        class C(A):
            baz = self.field2

        self.a_cls = A
        self.b_cls = B
        self.c_cls = C

    def test_fields(self):
        # pylint: disable=protected-access,no-member
        self.assertEqual({'baz': self.field}, self.a_cls._fields)
        self.assertEqual({'baz': self.field}, self.b_cls._fields)

    def test_fields_inheritance(self):
        # pylint: disable=protected-access,no-member
        self.assertEqual({'baz': self.field2}, self.c_cls._fields)

    def test_slots(self):
        self.assertEqual(('bar', 'baz'), self.a_cls.__slots__)
        self.assertEqual(('baz',), self.b_cls.__slots__)

    def test_orig_slots(self):
        # pylint: disable=protected-access,no-member
        self.assertEqual(('bar',), self.a_cls._orig_slots)
        self.assertEqual((), self.b_cls._orig_slots)


class JSONObjectWithFieldsTest(unittest.TestCase):
    """Tests for josepy.json_util.JSONObjectWithFields."""
    # pylint: disable=protected-access

    def setUp(self):
        from josepy.json_util import JSONObjectWithFields
        from josepy.json_util import Field

        class MockJSONObjectWithFields(JSONObjectWithFields):
            # pylint: disable=invalid-name,missing-docstring,no-self-argument
            # pylint: disable=too-few-public-methods
            x = Field('x', omitempty=True,
                      encoder=(lambda x: x * 2),
                      decoder=(lambda x: x / 2))
            y = Field('y')
            z = Field('Z')  # on purpose uppercase

            @y.encoder
            def y(value):
                if value == 500:
                    raise errors.SerializationError()
                return value

            @y.decoder
            def y(value):
                if value == 500:
                    raise errors.DeserializationError()
                return value

        # pylint: disable=invalid-name
        self.MockJSONObjectWithFields = MockJSONObjectWithFields
        self.mock = MockJSONObjectWithFields(x=None, y=2, z=3)

    def test_init_defaults(self):
        self.assertEqual(self.mock, self.MockJSONObjectWithFields(y=2, z=3))

    def test_encode(self):
        self.assertEqual(10, self.MockJSONObjectWithFields(
            x=5, y=0, z=0).encode("x"))

    def test_encode_wrong_field(self):
        self.assertRaises(errors.Error, self.mock.encode, 'foo')

    def test_encode_serialization_error_passthrough(self):
        self.assertRaises(
            errors.SerializationError,
            self.MockJSONObjectWithFields(y=500, z=None).encode, "y")

    def test_fields_to_partial_json_omits_empty(self):
        self.assertEqual(self.mock.fields_to_partial_json(), {'y': 2, 'Z': 3})

    def test_fields_from_json_fills_default_for_empty(self):
        self.assertEqual(
            {'x': None, 'y': 2, 'z': 3},
            self.MockJSONObjectWithFields.fields_from_json({'y': 2, 'Z': 3}))

    def test_fields_from_json_fails_on_missing(self):
        self.assertRaises(
            errors.DeserializationError,
            self.MockJSONObjectWithFields.fields_from_json, {'y': 0})
        self.assertRaises(
            errors.DeserializationError,
            self.MockJSONObjectWithFields.fields_from_json, {'Z': 0})
        self.assertRaises(
            errors.DeserializationError,
            self.MockJSONObjectWithFields.fields_from_json, {'x': 0, 'y': 0})
        self.assertRaises(
            errors.DeserializationError,
            self.MockJSONObjectWithFields.fields_from_json, {'x': 0, 'Z': 0})

    def test_fields_to_partial_json_encoder(self):
        self.assertEqual(
            self.MockJSONObjectWithFields(x=1, y=2, z=3).to_partial_json(),
            {'x': 2, 'y': 2, 'Z': 3})

    def test_fields_from_json_decoder(self):
        self.assertEqual(
            {'x': 2, 'y': 2, 'z': 3},
            self.MockJSONObjectWithFields.fields_from_json(
                {'x': 4, 'y': 2, 'Z': 3}))

    def test_fields_to_partial_json_error_passthrough(self):
        self.assertRaises(
            errors.SerializationError, self.MockJSONObjectWithFields(
                x=1, y=500, z=3).to_partial_json)

    def test_fields_from_json_error_passthrough(self):
        self.assertRaises(
            errors.DeserializationError,
            self.MockJSONObjectWithFields.from_json,
            {'x': 4, 'y': 500, 'Z': 3})


class DeEncodersTest(unittest.TestCase):
    def setUp(self):
        self.b64_cert = (
            u'MIIB3jCCAYigAwIBAgICBTkwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhM'
            u'CVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRIwEAYDVQQHDAlBbm4gQXJib3IxKz'
            u'ApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTWljaGlnYW4gYW5kIHRoZSBFRkYxF'
            u'DASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTE0MTIxMTIyMzQ0NVoXDTE0MTIx'
            u'ODIyMzQ0NVowdzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRI'
            u'wEAYDVQQHDAlBbm4gQXJib3IxKzApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTW'
            u'ljaGlnYW4gYW5kIHRoZSBFRkYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFwwD'
            u'QYJKoZIhvcNAQEBBQADSwAwSAJBAKx1c7RR7R_drnBSQ_zfx1vQLHUbFLh1'
            u'AQQQ5R8DZUXd36efNK79vukFhN9HFoHZiUvOjm0c-pVE6K-EdE_twuUCAwE'
            u'AATANBgkqhkiG9w0BAQsFAANBAC24z0IdwIVKSlntksllvr6zJepBH5fMnd'
            u'fk3XJp10jT6VE-14KNtjh02a56GoraAvJAT5_H67E8GvJ_ocNnB_o'
        )
        self.b64_csr = (
            u'MIIBXTCCAQcCAQAweTELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2F'
            u'uMRIwEAYDVQQHDAlBbm4gQXJib3IxDDAKBgNVBAoMA0VGRjEfMB0GA1UECw'
            u'wWVW5pdmVyc2l0eSBvZiBNaWNoaWdhbjEUMBIGA1UEAwwLZXhhbXBsZS5jb'
            u'20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEArHVztFHtH92ucFJD_N_HW9As'
            u'dRsUuHUBBBDlHwNlRd3fp580rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3'
            u'C5QIDAQABoCkwJwYJKoZIhvcNAQkOMRowGDAWBgNVHREEDzANggtleGFtcG'
            u'xlLmNvbTANBgkqhkiG9w0BAQsFAANBAHJH_O6BtC9aGzEVCMGOZ7z9iIRHW'
            u'Szr9x_bOzn7hLwsbXPAgO1QxEwL-X-4g20Gn9XBE1N9W6HCIEut2d8wACg'
        )

    def test_encode_b64jose(self):
        from josepy.json_util import encode_b64jose
        encoded = encode_b64jose(b'x')
        self.assertTrue(isinstance(encoded, six.string_types))
        self.assertEqual(u'eA', encoded)

    def test_decode_b64jose(self):
        from josepy.json_util import decode_b64jose
        decoded = decode_b64jose(u'eA')
        self.assertTrue(isinstance(decoded, six.binary_type))
        self.assertEqual(b'x', decoded)

    def test_decode_b64jose_padding_error(self):
        from josepy.json_util import decode_b64jose
        self.assertRaises(errors.DeserializationError, decode_b64jose, u'x')

    def test_decode_b64jose_size(self):
        from josepy.json_util import decode_b64jose
        self.assertEqual(b'foo', decode_b64jose(u'Zm9v', size=3))
        self.assertRaises(
            errors.DeserializationError, decode_b64jose, u'Zm9v', size=2)
        self.assertRaises(
            errors.DeserializationError, decode_b64jose, u'Zm9v', size=4)

    def test_decode_b64jose_minimum_size(self):
        from josepy.json_util import decode_b64jose
        self.assertEqual(b'foo', decode_b64jose(u'Zm9v', size=3, minimum=True))
        self.assertEqual(b'foo', decode_b64jose(u'Zm9v', size=2, minimum=True))
        self.assertRaises(errors.DeserializationError, decode_b64jose,
                          u'Zm9v', size=4, minimum=True)

    def test_encode_hex16(self):
        from josepy.json_util import encode_hex16
        encoded = encode_hex16(b'foo')
        self.assertEqual(u'666f6f', encoded)
        self.assertTrue(isinstance(encoded, six.string_types))

    def test_decode_hex16(self):
        from josepy.json_util import decode_hex16
        decoded = decode_hex16(u'666f6f')
        self.assertEqual(b'foo', decoded)
        self.assertTrue(isinstance(decoded, six.binary_type))

    def test_decode_hex16_minimum_size(self):
        from josepy.json_util import decode_hex16
        self.assertEqual(b'foo', decode_hex16(u'666f6f', size=3, minimum=True))
        self.assertEqual(b'foo', decode_hex16(u'666f6f', size=2, minimum=True))
        self.assertRaises(errors.DeserializationError, decode_hex16,
                          u'666f6f', size=4, minimum=True)

    def test_decode_hex16_odd_length(self):
        from josepy.json_util import decode_hex16
        self.assertRaises(errors.DeserializationError, decode_hex16, u'x')

    def test_encode_cert(self):
        from josepy.json_util import encode_cert
        self.assertEqual(self.b64_cert, encode_cert(CERT))

    def test_decode_cert(self):
        from josepy.json_util import decode_cert
        cert = decode_cert(self.b64_cert)
        self.assertTrue(isinstance(cert, util.ComparableX509))
        self.assertEqual(cert, CERT)
        self.assertRaises(errors.DeserializationError, decode_cert, u'')

    def test_encode_csr(self):
        from josepy.json_util import encode_csr
        self.assertEqual(self.b64_csr, encode_csr(CSR))

    def test_decode_csr(self):
        from josepy.json_util import decode_csr
        csr = decode_csr(self.b64_csr)
        self.assertTrue(isinstance(csr, util.ComparableX509))
        self.assertEqual(csr, CSR)
        self.assertRaises(errors.DeserializationError, decode_csr, u'')


class TypedJSONObjectWithFieldsTest(unittest.TestCase):

    def setUp(self):
        from josepy.json_util import TypedJSONObjectWithFields

        # pylint: disable=missing-docstring,abstract-method
        # pylint: disable=too-few-public-methods

        class MockParentTypedJSONObjectWithFields(TypedJSONObjectWithFields):
            TYPES = {}
            type_field_name = 'type'

        @MockParentTypedJSONObjectWithFields.register
        class MockTypedJSONObjectWithFields(
                MockParentTypedJSONObjectWithFields):
            typ = 'test'
            __slots__ = ('foo',)

            @classmethod
            def fields_from_json(cls, jobj):
                return {'foo': jobj['foo']}

            def fields_to_partial_json(self):
                return {'foo': self.foo}

        self.parent_cls = MockParentTypedJSONObjectWithFields
        self.msg = MockTypedJSONObjectWithFields(foo='bar')

    def test_to_partial_json(self):
        self.assertEqual(self.msg.to_partial_json(), {
            'type': 'test',
            'foo': 'bar',
        })

    def test_from_json_non_dict_fails(self):
        for value in [[], (), 5, "asd"]:  # all possible input types
            self.assertRaises(
                errors.DeserializationError, self.parent_cls.from_json, value)

    def test_from_json_dict_no_type_fails(self):
        self.assertRaises(
            errors.DeserializationError, self.parent_cls.from_json, {})

    def test_from_json_unknown_type_fails(self):
        self.assertRaises(errors.UnrecognizedTypeError,
                          self.parent_cls.from_json, {'type': 'bar'})

    def test_from_json_returns_obj(self):
        self.assertEqual({'foo': 'bar'}, self.parent_cls.from_json(
            {'type': 'test', 'foo': 'bar'}))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
