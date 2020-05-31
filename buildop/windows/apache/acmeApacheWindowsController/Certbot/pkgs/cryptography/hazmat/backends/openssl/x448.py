# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.backends.openssl.utils import _evp_pkey_derive
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PrivateKey, X448PublicKey
)

_X448_KEY_SIZE = 56


@utils.register_interface(X448PublicKey)
class _X448PublicKey(object):
    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_bytes(self, encoding, format):
        if (
            encoding is serialization.Encoding.Raw or
            format is serialization.PublicFormat.Raw
        ):
            if (
                encoding is not serialization.Encoding.Raw or
                format is not serialization.PublicFormat.Raw
            ):
                raise ValueError(
                    "When using Raw both encoding and format must be Raw"
                )

            return self._raw_public_bytes()

        if (
            encoding in serialization._PEM_DER and
            format is not serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError(
                "format must be SubjectPublicKeyInfo when encoding is PEM or "
                "DER"
            )

        return self._backend._public_key_bytes(
            encoding, format, self, self._evp_pkey, None
        )

    def _raw_public_bytes(self):
        buf = self._backend._ffi.new("unsigned char []", _X448_KEY_SIZE)
        buflen = self._backend._ffi.new("size_t *", _X448_KEY_SIZE)
        res = self._backend._lib.EVP_PKEY_get_raw_public_key(
            self._evp_pkey, buf, buflen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == _X448_KEY_SIZE)
        return self._backend._ffi.buffer(buf, _X448_KEY_SIZE)[:]


@utils.register_interface(X448PrivateKey)
class _X448PrivateKey(object):
    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_key(self):
        buf = self._backend._ffi.new("unsigned char []", _X448_KEY_SIZE)
        buflen = self._backend._ffi.new("size_t *", _X448_KEY_SIZE)
        res = self._backend._lib.EVP_PKEY_get_raw_public_key(
            self._evp_pkey, buf, buflen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == _X448_KEY_SIZE)
        return self._backend.x448_load_public_bytes(buf)

    def exchange(self, peer_public_key):
        if not isinstance(peer_public_key, X448PublicKey):
            raise TypeError("peer_public_key must be X448PublicKey.")

        return _evp_pkey_derive(
            self._backend, self._evp_pkey, peer_public_key
        )

    def private_bytes(self, encoding, format, encryption_algorithm):
        if (
            encoding is serialization.Encoding.Raw or
            format is serialization.PublicFormat.Raw
        ):
            if (
                format is not serialization.PrivateFormat.Raw or
                encoding is not serialization.Encoding.Raw or not
                isinstance(encryption_algorithm, serialization.NoEncryption)
            ):
                raise ValueError(
                    "When using Raw both encoding and format must be Raw "
                    "and encryption_algorithm must be NoEncryption()"
                )

            return self._raw_private_bytes()

        if (
            encoding in serialization._PEM_DER and
            format is not serialization.PrivateFormat.PKCS8
        ):
            raise ValueError(
                "format must be PKCS8 when encoding is PEM or DER"
            )

        return self._backend._private_key_bytes(
            encoding, format, encryption_algorithm, self._evp_pkey, None
        )

    def _raw_private_bytes(self):
        buf = self._backend._ffi.new("unsigned char []", _X448_KEY_SIZE)
        buflen = self._backend._ffi.new("size_t *", _X448_KEY_SIZE)
        res = self._backend._lib.EVP_PKEY_get_raw_private_key(
            self._evp_pkey, buf, buflen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == _X448_KEY_SIZE)
        return self._backend._ffi.buffer(buf, _X448_KEY_SIZE)[:]
