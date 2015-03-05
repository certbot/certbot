"""Tests for letsencrypt.acme.util."""
import functools
import json
import os
import pkg_resources
import unittest

import M2Crypto
import zope.interface

from letsencrypt.acme import errors
from letsencrypt.acme import interfaces


CERT = M2Crypto.X509.load_cert(pkg_resources.resource_filename(
    'letsencrypt.client.tests', os.path.join('testdata', 'cert.pem')))
CSR = M2Crypto.X509.load_request(pkg_resources.resource_filename(
    'letsencrypt.client.tests', os.path.join('testdata', 'csr.pem')))


class DumpIJSONSerializableTest(unittest.TestCase):
    """Tests for letsencrypt.acme.util.dump_ijsonserializable."""

    class MockJSONSerialiazable(object):
        # pylint: disable=missing-docstring,too-few-public-methods,no-self-use
        zope.interface.implements(interfaces.IJSONSerializable)

        def to_json(self):
            return [3, 2, 1]

    @classmethod
    def _call(cls, obj):
        from letsencrypt.acme.util import dump_ijsonserializable
        return json.dumps(obj, default=dump_ijsonserializable)

    def test_json_type(self):
        self.assertEqual('5', self._call(5))

    def test_ijsonserializable(self):
        self.assertEqual('[3, 2, 1]', self._call(self.MockJSONSerialiazable()))

    def test_raises_type_error(self):
        self.assertRaises(TypeError, self._call, object())


class ImmutableMapTest(unittest.TestCase):
    """Tests for letsencrypt.acme.util.ImmutableMap."""

    def setUp(self):
        # pylint: disable=invalid-name,too-few-public-methods
        # pylint: disable=missing-docstring
        from letsencrypt.acme.util import ImmutableMap

        class A(ImmutableMap):
            __slots__ = ('x', 'y')

        class B(ImmutableMap):
            __slots__ = ('x', 'y')

        self.A = A
        self.B = B

        self.a1 = self.A(x=1, y=2)
        self.a1_swap = self.A(y=2, x=1)
        self.a2 = self.A(x=3, y=4)
        self.b = self.B(x=1, y=2)

    def test_order_of_args_does_not_matter(self):
        self.assertEqual(self.a1, self.a1_swap)

    def test_type_error_on_missing(self):
        self.assertRaises(TypeError, self.A, x=1)
        self.assertRaises(TypeError, self.A, y=2)

    def test_type_error_on_unrecognized(self):
        self.assertRaises(TypeError, self.A, x=1, z=2)
        self.assertRaises(TypeError, self.A, x=1, y=2, z=3)

    def test_get_attr(self):
        self.assertEqual(1, self.a1.x)
        self.assertEqual(2, self.a1.y)
        self.assertEqual(1, self.a1_swap.x)
        self.assertEqual(2, self.a1_swap.y)

    def test_set_attr_raises_attribute_error(self):
        self.assertRaises(
            AttributeError, functools.partial(self.a1.__setattr__, 'x'), 10)

    def test_equal(self):
        self.assertEqual(self.a1, self.a1)
        self.assertEqual(self.a2, self.a2)
        self.assertNotEqual(self.a1, self.a2)

    def test_same_slots_diff_cls_not_equal(self):
        self.assertEqual(self.a1.x, self.b.x)
        self.assertEqual(self.a1.y, self.b.y)
        self.assertNotEqual(self.a1, self.b)

    def test_hash(self):
        self.assertEqual(hash((1, 2)), hash(self.a1))

    def test_unhashable(self):
        self.assertRaises(TypeError, self.A(x=1, y={}).__hash__)

    def test_repr(self):
        self.assertEqual('A(x=1, y=2)', repr(self.a1))
        self.assertEqual('A(x=1, y=2)', repr(self.a1_swap))
        self.assertEqual('B(x=1, y=2)', repr(self.b))
        self.assertEqual("B(x='foo', y='bar')", repr(self.B(x='foo', y='bar')))


class EncodersAndDecodersTest(unittest.TestCase):
    """Tests for encoders and decoders from letsencrypt.acme.util"""
    # pylint: disable=protected-access

    def setUp(self):
        self.b64_cert = (
            'MIIB3jCCAYigAwIBAgICBTkwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhM'
            'CVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRIwEAYDVQQHDAlBbm4gQXJib3IxKz'
            'ApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTWljaGlnYW4gYW5kIHRoZSBFRkYxF'
            'DASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTE0MTIxMTIyMzQ0NVoXDTE0MTIx'
            'ODIyMzQ0NVowdzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRI'
            'wEAYDVQQHDAlBbm4gQXJib3IxKzApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTW'
            'ljaGlnYW4gYW5kIHRoZSBFRkYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFwwD'
            'QYJKoZIhvcNAQEBBQADSwAwSAJBAKx1c7RR7R_drnBSQ_zfx1vQLHUbFLh1'
            'AQQQ5R8DZUXd36efNK79vukFhN9HFoHZiUvOjm0c-pVE6K-EdE_twuUCAwE'
            'AATANBgkqhkiG9w0BAQsFAANBAC24z0IdwIVKSlntksllvr6zJepBH5fMnd'
            'fk3XJp10jT6VE-14KNtjh02a56GoraAvJAT5_H67E8GvJ_ocNnB_o'
        )
        self.b64_csr = (
            'MIIBXTCCAQcCAQAweTELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2F'
            'uMRIwEAYDVQQHDAlBbm4gQXJib3IxDDAKBgNVBAoMA0VGRjEfMB0GA1UECw'
            'wWVW5pdmVyc2l0eSBvZiBNaWNoaWdhbjEUMBIGA1UEAwwLZXhhbXBsZS5jb'
            '20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEArHVztFHtH92ucFJD_N_HW9As'
            'dRsUuHUBBBDlHwNlRd3fp580rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3'
            'C5QIDAQABoCkwJwYJKoZIhvcNAQkOMRowGDAWBgNVHREEDzANggtleGFtcG'
            'xlLmNvbTANBgkqhkiG9w0BAQsFAANBAHJH_O6BtC9aGzEVCMGOZ7z9iIRHW'
            'Szr9x_bOzn7hLwsbXPAgO1QxEwL-X-4g20Gn9XBE1N9W6HCIEut2d8wACg'
        )

    def test_decode_b64_jose_padding_error(self):
        from letsencrypt.acme.util import decode_b64jose
        self.assertRaises(errors.ValidationError, decode_b64jose, 'x')

    def test_decode_b64_jose_size(self):
        from letsencrypt.acme.util import decode_b64jose
        self.assertEqual('foo', decode_b64jose('Zm9v', size=3))
        self.assertRaises(
            errors.ValidationError, decode_b64jose, 'Zm9v', size=2)
        self.assertRaises(
            errors.ValidationError, decode_b64jose, 'Zm9v', size=4)

    def test_decode_b64_jose_minimum_size(self):
        from letsencrypt.acme.util import decode_b64jose
        self.assertEqual('foo', decode_b64jose('Zm9v', size=3, minimum=True))
        self.assertEqual('foo', decode_b64jose('Zm9v', size=2, minimum=True))
        self.assertRaises(errors.ValidationError, decode_b64jose,
                          'Zm9v', size=4, minimum=True)

    def test_decode_hex16(self):
        from letsencrypt.acme.util import decode_hex16
        self.assertEqual('foo', decode_hex16('666f6f'))

    def test_decode_hex16_minimum_size(self):
        from letsencrypt.acme.util import decode_hex16
        self.assertEqual('foo', decode_hex16('666f6f', size=3, minimum=True))
        self.assertEqual('foo', decode_hex16('666f6f', size=2, minimum=True))
        self.assertRaises(errors.ValidationError, decode_hex16,
                          '666f6f', size=4, minimum=True)

    def test_decode_hex16_odd_length(self):
        from letsencrypt.acme.util import decode_hex16
        self.assertRaises(errors.ValidationError, decode_hex16, 'x')

    def test_encode_cert(self):
        from letsencrypt.acme.util import encode_cert
        self.assertEqual(self.b64_cert, encode_cert(CERT))

    def test_decode_cert(self):
        from letsencrypt.acme.util import ComparableX509
        from letsencrypt.acme.util import decode_cert
        cert = decode_cert(self.b64_cert)
        self.assertTrue(isinstance(cert, ComparableX509))
        self.assertEqual(cert, CERT)
        self.assertRaises(errors.ValidationError, decode_cert, '')

    def test_encode_csr(self):
        from letsencrypt.acme.util import encode_csr
        self.assertEqual(self.b64_csr, encode_csr(CSR))

    def test_decode_csr(self):
        from letsencrypt.acme.util import ComparableX509
        from letsencrypt.acme.util import decode_csr
        csr = decode_csr(self.b64_csr)
        self.assertTrue(isinstance(csr, ComparableX509))
        self.assertEqual(csr, CSR)
        self.assertRaises(errors.ValidationError, decode_csr, '')


class TypedACMEObjectTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.util import TypedACMEObject

        # pylint: disable=missing-docstring,abstract-method
        # pylint: disable=too-few-public-methods

        class MockParentTypedACMEObject(TypedACMEObject):
            TYPES = {}

        @MockParentTypedACMEObject.register
        class MockTypedACMEObject(MockParentTypedACMEObject):
            acme_type = 'test'

            @classmethod
            def from_valid_json(cls, unused_obj):
                return '!'

            def _fields_to_json(self):
                return {'foo': 'bar'}

        self.parent_cls = MockParentTypedACMEObject
        self.msg = MockTypedACMEObject()

    def test_to_json(self):
        self.assertEqual(self.msg.to_json(), {
            'type': 'test',
            'foo': 'bar',
        })

    def test_from_json_unknown_type_fails(self):
        self.assertRaises(errors.UnrecognizedTypeError,
                          self.parent_cls.from_valid_json, {'type': 'bar'})

    def test_from_json_returns_obj(self):
        self.assertEqual(self.parent_cls.from_valid_json({'type': 'test'}), '!')


if __name__ == '__main__':
    unittest.main()
