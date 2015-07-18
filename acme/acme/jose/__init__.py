"""Javascript Object Signing and Encryption (jose).

This package is a Python implementation of the stadards developed by
IETF `Javascript Object Signing and Encryption (Active WG)`_, in
particular the following RFCs:

  - `JSON Web Algorithms (JWA)`_
  - `JSON Web Key (JWK)`_
  - `JSON Web Signature (JWS)`_


.. _`Javascript Object Signing and Encryption (Active WG)`:
  https://tools.ietf.org/wg/jose/

.. _`JSON Web Algorithms (JWA)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-algorithms/

.. _`JSON Web Key (JWK)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-key/

.. _`JSON Web Signature (JWS)`:
  https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-signature/

"""
from acme.jose.b64 import (
    b64decode,
    b64encode,
)

from acme.jose.errors import (
    DeserializationError,
    SerializationError,
    Error,
    UnrecognizedTypeError,
)

from acme.jose.interfaces import JSONDeSerializable

from acme.jose.json_util import (
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

from acme.jose.jwa import (
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

from acme.jose.jwk import (
    JWK,
    JWKRSA,
)

from acme.jose.jws import (
    Header,
    JWS,
    Signature,
)

from acme.jose.util import (
    ComparableX509,
    ComparableKey,
    ComparableRSAKey,
    ImmutableMap,
)
