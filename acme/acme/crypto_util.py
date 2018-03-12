"""Crypto utilities."""
import binascii
import contextlib
import logging
import os
import re
import socket

import OpenSSL
import josepy as jose


from acme import errors


logger = logging.getLogger(__name__)

# TLSSNI01 certificate serving and probing is not affected by SSL
# vulnerabilities: prober needs to check certificate for expected
# contents anyway. Working SNI is the only thing that's necessary for
# the challenge and thus scoping down SSL/TLS method (version) would
# cause interoperability issues: TLSv1_METHOD is only compatible with
# TLSv1_METHOD, while SSLv23_METHOD is compatible with all other
# methods, including TLSv2_METHOD (read more at
# https://www.openssl.org/docs/ssl/SSLv23_method.html). _serve_sni
# should be changed to use "set_options" to disable SSLv2 and SSLv3,
# in case it's used for things other than probing/serving!
_DEFAULT_TLSSNI01_SSL_METHOD = OpenSSL.SSL.SSLv23_METHOD  # type: ignore


class SSLSocket(object):  # pylint: disable=too-few-public-methods
    """SSL wrapper for sockets.

    :ivar socket sock: Original wrapped socket.
    :ivar dict certs: Mapping from domain names (`bytes`) to
        `OpenSSL.crypto.X509`.
    :ivar method: See `OpenSSL.SSL.Context` for allowed values.

    """
    def __init__(self, sock, certs, method=_DEFAULT_TLSSNI01_SSL_METHOD):
        self.sock = sock
        self.certs = certs
        self.method = method

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def _pick_certificate_cb(self, connection):
        """SNI certificate callback.

        This method will set a new OpenSSL context object for this
        connection when an incoming connection provides an SNI name
        (in order to serve the appropriate certificate, if any).

        :param connection: The TLS connection object on which the SNI
            extension was received.
        :type connection: :class:`OpenSSL.Connection`

        """
        server_name = connection.get_servername()
        try:
            key, cert = self.certs[server_name]
        except KeyError:
            logger.debug("Server name (%s) not recognized, dropping SSL",
                         server_name)
            return
        new_context = OpenSSL.SSL.Context(self.method)
        new_context.set_options(OpenSSL.SSL.OP_NO_SSLv2)
        new_context.set_options(OpenSSL.SSL.OP_NO_SSLv3)
        new_context.use_privatekey(key)
        new_context.use_certificate(cert)
        connection.set_context(new_context)

    class FakeConnection(object):
        """Fake OpenSSL.SSL.Connection."""

        # pylint: disable=too-few-public-methods,missing-docstring

        def __init__(self, connection):
            self._wrapped = connection

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

        def shutdown(self, *unused_args):
            # OpenSSL.SSL.Connection.shutdown doesn't accept any args
            return self._wrapped.shutdown()

    def accept(self):  # pylint: disable=missing-docstring
        sock, addr = self.sock.accept()

        context = OpenSSL.SSL.Context(self.method)
        context.set_options(OpenSSL.SSL.OP_NO_SSLv2)
        context.set_options(OpenSSL.SSL.OP_NO_SSLv3)
        context.set_tlsext_servername_callback(self._pick_certificate_cb)

        ssl_sock = self.FakeConnection(OpenSSL.SSL.Connection(context, sock))
        ssl_sock.set_accept_state()

        logger.debug("Performing handshake with %s", addr)
        try:
            ssl_sock.do_handshake()
        except OpenSSL.SSL.Error as error:
            # _pick_certificate_cb might have returned without
            # creating SSL context (wrong server name)
            raise socket.error(error)

        return ssl_sock, addr


def probe_sni(name, host, port=443, timeout=300,
              method=_DEFAULT_TLSSNI01_SSL_METHOD, source_address=('', 0)):
    """Probe SNI server for SSL certificate.

    :param bytes name: Byte string to send as the server name in the
        client hello message.
    :param bytes host: Host to connect to.
    :param int port: Port to connect to.
    :param int timeout: Timeout in seconds.
    :param method: See `OpenSSL.SSL.Context` for allowed values.
    :param tuple source_address: Enables multi-path probing (selection
        of source interface). See `socket.creation_connection` for more
        info. Available only in Python 2.7+.

    :raises acme.errors.Error: In case of any problems.

    :returns: SSL certificate presented by the server.
    :rtype: OpenSSL.crypto.X509

    """
    context = OpenSSL.SSL.Context(method)
    context.set_timeout(timeout)

    socket_kwargs = {'source_address': source_address}

    host_protocol_agnostic = None if host == '::' or host == '0' else host

    try:
        # pylint: disable=star-args
        logger.debug("Attempting to connect to %s:%d%s.", host_protocol_agnostic, port,
            " from {0}:{1}".format(source_address[0], source_address[1]) if \
            socket_kwargs else "")
        sock = socket.create_connection((host_protocol_agnostic, port), **socket_kwargs)
    except socket.error as error:
        raise errors.Error(error)

    with contextlib.closing(sock) as client:
        client_ssl = OpenSSL.SSL.Connection(context, client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(name)  # pyOpenSSL>=0.13
        try:
            client_ssl.do_handshake()
            client_ssl.shutdown()
        except OpenSSL.SSL.Error as error:
            raise errors.Error(error)
    return client_ssl.get_peer_certificate()

def make_csr(private_key_pem, domains, must_staple=False):
    """Generate a CSR containing a list of domains as subjectAltNames.

    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :param bool must_staple: Whether to include the TLS Feature extension (aka
        OCSP Must Staple: https://tools.ietf.org/html/rfc7633).
    :returns: buffer PEM-encoded Certificate Signing Request.
    """
    private_key = OpenSSL.crypto.load_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, private_key_pem)
    csr = OpenSSL.crypto.X509Req()
    extensions = [
        OpenSSL.crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join('DNS:' + d for d in domains).encode('ascii')
        ),
    ]
    if must_staple:
        extensions.append(OpenSSL.crypto.X509Extension(
            b"1.3.6.1.5.5.7.1.24",
            critical=False,
            value=b"DER:30:03:02:01:05"))
    csr.add_extensions(extensions)
    csr.set_pubkey(private_key)
    csr.set_version(2)
    csr.sign(private_key, 'sha256')
    return OpenSSL.crypto.dump_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, csr)

def _pyopenssl_cert_or_req_all_names(loaded_cert_or_req):
    common_name = loaded_cert_or_req.get_subject().CN
    sans = _pyopenssl_cert_or_req_san(loaded_cert_or_req)

    if common_name is None:
        return sans
    else:
        return [common_name] + [d for d in sans if d != common_name]

def _pyopenssl_cert_or_req_san(cert_or_req):
    """Get Subject Alternative Names from certificate or CSR using pyOpenSSL.

    .. todo:: Implement directly in PyOpenSSL!

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `OpenSSL.crypto.X509` or `OpenSSL.crypto.X509Req`.

    :returns: A list of Subject Alternative Names.
    :rtype: `list` of `unicode`

    """
    # This function finds SANs by dumping the certificate/CSR to text and
    # searching for "X509v3 Subject Alternative Name" in the text. This method
    # is used to support PyOpenSSL version 0.13 where the
    # `_subjectAltNameString` and `get_extensions` methods are not available
    # for CSRs.

    # constants based on PyOpenSSL certificate/CSR text dump
    part_separator = ":"
    parts_separator = ", "
    prefix = "DNS" + part_separator

    if isinstance(cert_or_req, OpenSSL.crypto.X509):
        func = OpenSSL.crypto.dump_certificate
    else:
        func = OpenSSL.crypto.dump_certificate_request
    text = func(OpenSSL.crypto.FILETYPE_TEXT, cert_or_req).decode("utf-8")
    # WARNING: this function does not support multiple SANs extensions.
    # Multiple X509v3 extensions of the same type is disallowed by RFC 5280.
    match = re.search(r"X509v3 Subject Alternative Name:(?: critical)?\s*(.*)", text)
    # WARNING: this function assumes that no SAN can include
    # parts_separator, hence the split!
    sans_parts = [] if match is None else match.group(1).split(parts_separator)

    return [part.split(part_separator)[1]
            for part in sans_parts if part.startswith(prefix)]


def gen_ss_cert(key, domains, not_before=None,
                validity=(7 * 24 * 60 * 60), force_san=True):
    """Generate new self-signed certificate.

    :type domains: `list` of `unicode`
    :param OpenSSL.crypto.PKey key:
    :param bool force_san:

    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.

    """
    assert domains, "Must provide one or more hostnames for the cert."
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(int(binascii.hexlify(os.urandom(16)), 16))
    cert.set_version(2)

    extensions = [
        OpenSSL.crypto.X509Extension(
            b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    ]

    cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    if force_san or len(domains) > 1:
        extensions.append(OpenSSL.crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=b", ".join(b"DNS:" + d.encode() for d in domains)
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert

def dump_pyopenssl_chain(chain, filetype=OpenSSL.crypto.FILETYPE_PEM):
    """Dump certificate chain into a bundle.

    :param list chain: List of `OpenSSL.crypto.X509` (or wrapped in
        :class:`josepy.util.ComparableX509`).

    :returns: certificate chain bundle
    :rtype: bytes

    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...

    def _dump_cert(cert):
        if isinstance(cert, jose.ComparableX509):
            # pylint: disable=protected-access
            cert = cert.wrapped
        return OpenSSL.crypto.dump_certificate(filetype, cert)

    # assumes that OpenSSL.crypto.dump_certificate includes ending
    # newline character
    return b"".join(_dump_cert(cert) for cert in chain)
