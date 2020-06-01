"""Javascript Object Signing and Encryption (JOSE).

This package is a Python implementation of the standards developed by
IETF `Javascript Object Signing and Encryption (Active WG)`_, in
particular the following RFCs:

- `JSON Web Algorithms (JWA)`_
- `JSON Web Key (JWK)`_
- `JSON Web Signature (JWS)`_

Originally developed as part of the ACME_ protocol implementation.

.. _`Javascript Object Signing and Encryption (Active WG)`:
  https://tools.ietf.org/wg/jose/

.. _`JSON Web Algorithms (JWA)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-algorithms/

.. _`JSON Web Key (JWK)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-key/

.. _`JSON Web Signature (JWS)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-signature/

.. _ACME: https://pypi.python.org/pypi/acme

"""
# flake8: noqa
from josepy.b64 import (
    b64decode,
    b64encode,
)

from josepy.errors import (
    DeserializationError,
    SerializationError,
    Error,
    UnrecognizedTypeError,
)

from josepy.interfaces import JSONDeSerializable

from josepy.json_util import (
    Field,
    JSONObjectWithFields,
    TypedJSONObjectWithFields,
    decode_b64jose,
    decode_cert,
    decode_csr,
    decode_hex16,
    encode_b64jose,
    encode_cert,
    encode_csr,
    encode_hex16,
)

from josepy.jwa import (
    HS256,
    HS384,
    HS512,
    JWASignature,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
)

from josepy.jwk import (
    JWK,
    JWKRSA,
)

from josepy.jws import (
    Header,
    JWS,
    Signature,
)

from josepy.util import (
    ComparableX509,
    ComparableKey,
    ComparableRSAKey,
    ImmutableMap,
)
