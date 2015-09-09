"""Crypto utilities."""
import contextlib
import logging
import socket
import sys

from six.moves import range  # pylint: disable=import-error,redefined-builtin

import OpenSSL

from acme import errors


logger = logging.getLogger(__name__)

# DVSNI certificate serving and probing is not affected by SSL
# vulnerabilities: prober needs to check certificate for expected
# contents anyway. Working SNI is the only thing that's necessary for
# the challenge and thus scoping down SSL/TLS method (version) would
# cause interoperability issues: TLSv1_METHOD is only compatible with
# TLSv1_METHOD, while SSLv23_METHOD is compatible with all other
# methods, including TLSv2_METHOD (read more at
# https://www.openssl.org/docs/ssl/SSLv23_method.html). _serve_sni
# should be changed to use "set_options" to disable SSLv2 and SSLv3,
# in case it's used for things other than probing/serving!
_DEFAULT_DVSNI_SSL_METHOD = OpenSSL.SSL.SSLv23_METHOD


def _serve_sni(certs, sock, reuseaddr=True, method=_DEFAULT_DVSNI_SSL_METHOD,
               accept=None):
    """Start SNI-enabled server, that drops connection after handshake.

    :param certs: Mapping from SNI name to ``(key, cert)`` `tuple`.
    :param sock: Already bound socket.
    :param bool reuseaddr: Should `socket.SO_REUSEADDR` be set?
    :param method: See `OpenSSL.SSL.Context` for allowed values.
    :param accept: Callable that doesn't take any arguments and
        returns ``True`` if more connections should be served.

    """
    def _pick_certificate(connection):
        try:
            key, cert = certs[connection.get_servername()]
        except KeyError:
            return
        new_context = OpenSSL.SSL.Context(method)
        new_context.use_privatekey(key)
        new_context.use_certificate(cert)
        connection.set_context(new_context)

    if reuseaddr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.listen(1)  # TODO: add func arg?

    while accept is None or accept():
        server, addr = sock.accept()
        logger.debug('Received connection from %s', addr)

        with contextlib.closing(server):
            context = OpenSSL.SSL.Context(method)
            context.set_tlsext_servername_callback(_pick_certificate)

            server_ssl = OpenSSL.SSL.Connection(context, server)
            server_ssl.set_accept_state()
            try:
                server_ssl.do_handshake()
                server_ssl.shutdown()
            except OpenSSL.SSL.Error as error:
                raise errors.Error(error)


def probe_sni(name, host, port=443, timeout=300,
              method=_DEFAULT_DVSNI_SSL_METHOD, source_address=('0', 0)):
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

    socket_kwargs = {} if sys.version_info < (2, 7) else {
        'source_address': source_address}

    try:
        # pylint: disable=star-args
        sock = socket.create_connection((host, port), **socket_kwargs)
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
    # constants based on implementation of
    # OpenSSL.crypto.X509Error._subjectAltNameString
    parts_separator = ", "
    part_separator = ":"
    extension_short_name = b"subjectAltName"

    if hasattr(cert_or_req, 'get_extensions'):  # X509Req
        extensions = cert_or_req.get_extensions()
    else:  # X509
        extensions = [cert_or_req.get_extension(i)
                      for i in range(cert_or_req.get_extension_count())]

    # pylint: disable=protected-access,no-member
    label = OpenSSL.crypto.X509Extension._prefixes[OpenSSL.crypto._lib.GEN_DNS]
    assert parts_separator not in label
    prefix = label + part_separator

    san_extensions = [
        ext._subjectAltNameString().split(parts_separator)
        for ext in extensions if ext.get_short_name() == extension_short_name]
    # WARNING: this function assumes that no SAN can include
    # parts_separator, hence the split!

    return [part.split(part_separator)[1] for parts in san_extensions
            for part in parts if part.startswith(prefix)]


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
    cert.set_serial_number(1337)
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
