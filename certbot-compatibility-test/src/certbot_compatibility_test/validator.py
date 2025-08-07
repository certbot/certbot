"""Validators to determine the current webserver configuration"""
import contextlib
import logging
import socket
from typing import cast
from collections.abc import Mapping
from typing import Optional
from typing import Tuple
from typing import Union

from cryptography import x509
from OpenSSL import SSL
import requests

from acme import errors as acme_errors

logger = logging.getLogger(__name__)


_VALIDATION_TIMEOUT = 10


class Validator:
    """Collection of functions to test a live webserver's configuration"""

    def certificate(self, cert: x509.Certificate, name: Union[str, bytes],
                    alt_host: Optional[str] = None, port: int = 443) -> bool:
        """Verifies the certificate presented at name is cert"""
        if alt_host is None:
            # In fact, socket.gethostbyname accepts both bytes and str, but types do not know that.
            host = socket.gethostbyname(cast(str, name)).encode()
        elif isinstance(alt_host, bytes):
            host = alt_host
        else:
            host = alt_host.encode()
        name = name if isinstance(name, bytes) else name.encode()

        try:
            presented_cert = _probe_sni(name, host, port)
        except acme_errors.Error as error:
            logger.exception(str(error))
            return False

        return presented_cert == cert

    def redirect(self, name: str, port: int = 80,
                 headers: Optional[Mapping[str, str]] = None) -> bool:
        """Test whether webserver redirects to secure connection."""
        url = f"http://{name}:{port}"
        if headers:
            response = requests.get(url, headers=headers,
                                    allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)
        else:
            response = requests.get(url, allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)

        redirect_location = response.headers.get("location", "")
        # We're checking that the redirect we added behaves correctly.
        # It's okay for some server configuration to redirect to an
        # http URL, as long as it's on some other domain.
        if not redirect_location.startswith("https://"):
            return False

        if response.status_code != 301:
            logger.error("Server did not redirect with permanent code")
            return False

        return True

    def any_redirect(self, name: str, port: int = 80,
                     headers: Optional[Mapping[str, str]] = None) -> bool:
        """Test whether webserver redirects."""
        url = f"http://{name}:{port}"
        if headers:
            response = requests.get(url, headers=headers,
                                    allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)
        else:
            response = requests.get(url, allow_redirects=False,
                                    timeout=_VALIDATION_TIMEOUT)

        return response.status_code in range(300, 309)

    def hsts(self, name: str) -> bool:
        """Test for HTTP Strict Transport Security header"""
        headers = requests.get("https://" + name,
                               timeout=_VALIDATION_TIMEOUT).headers
        hsts_header = headers.get("strict-transport-security")

        if not hsts_header:
            return False

        # Split directives following RFC6797, section 6.1
        directives = [d.split("=") for d in hsts_header.split(";")]
        max_age = [d for d in directives if d[0] == "max-age"]

        if not max_age:
            logger.error("Server responded with invalid HSTS header field")
            return False

        try:
            max_age_value = int(max_age[0][1])
        except ValueError:
            logger.error("Server responded with invalid HSTS header field")
            return False

        # Test whether HSTS does not expire for at least two weeks.
        if max_age_value <= (2 * 7 * 24 * 3600):
            logger.error("HSTS should not expire in less than two weeks")
            return False

        return True

    def ocsp_stapling(self, name: str) -> None:
        """Verify ocsp stapling for domain."""
        raise NotImplementedError()



def _probe_sni(name: bytes, host: bytes, port: int = 443) -> x509.Certificate:
    """Probe SNI server for SSL certificate.

    :param bytes name: Byte string to send as the server name in the
        client hello message.
    :param bytes host: Host to connect to.
    :param int port: Port to connect to.

    :raises acme.errors.Error: In case of any problems.

    :returns: SSL certificate presented by the server.
    :rtype: cryptography.x509.Certificate

    """

    # Default SSL method selected here is the most compatible, while secure
    # SSL method: TLSv1_METHOD is only compatible with
    # TLSv1_METHOD, while TLS_method is compatible with all other
    # methods, including TLSv2_METHOD (read more at
    # https://docs.openssl.org/master/man3/SSL_CTX_new/#notes). _serve_sni
    # should be changed to use "set_options" to disable SSLv2 and SSLv3,
    # in case it's used for things other than probing/serving!
    context = SSL.Context(SSL.TLS_METHOD)
    context.set_timeout(300) # timeout in seconds

    # Enables multi-path probing (selection
    # of source interface). See `socket.creation_connection` for more
    # info. Available only in Python 2.7+.
    source_address: Tuple[str, int] = ('', 0)
    socket_kwargs = {'source_address': source_address}

    try:
        logger.debug(
            "Attempting to connect to %s:%d%s.", host, port,
            f" from {source_address[0]}:{source_address[1]}" if any(source_address) else ""
        )
        socket_tuple: Tuple[bytes, int] = (host, port)
        sock = socket.create_connection(socket_tuple, **socket_kwargs)  # type: ignore[arg-type]
    except OSError as error:
        raise acme_errors.Error(error)

    with contextlib.closing(sock) as client:
        client_ssl = SSL.Connection(context, client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(name)  # pyOpenSSL>=0.13
        try:
            client_ssl.do_handshake()
            client_ssl.shutdown()
        except SSL.Error as error:
            raise acme_errors.Error(error)
    cert = client_ssl.get_peer_certificate()
    assert cert # Appease mypy. We would have crashed out by now if there was no certificate.
    return cert.to_cryptography()
