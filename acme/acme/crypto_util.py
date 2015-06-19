"""Crypto utilities."""
import socket

import OpenSSL


def _probe_sni(server_hostname, host, port, timeout=10,
               method=OpenSSL.SSL.SSLv23_METHOD):
    sock = socket.create_connection((host, port), source_address=('0', 0))
    context = OpenSSL.SSL.Context(method)
    context.set_timeout(timeout)
    connection = OpenSSL.SSL.Connection(context, sock)
    connection.set_tlsext_host_name(server_hostname)  # pyOpenSSL>=0.13
    connection.set_connect_state()
    connection.do_handshake()
    cert = connection.get_peer_certificate()
    sock.close()
    # TODO: shutdown()
    return cert


def _pyopenssl_cert_or_req_san(cert_or_req):
    """Get Subject Alternative Names from certificate or CSR using pyOpenSSL.

    .. todo:: Implement directly in PyOpenSSL!

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `OpenSSL.crypto.X509` or `OpenSSL.crypto.X509Req`.

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    # constants based on implementation of
    # OpenSSL.crypto.X509Error._subjectAltNameString
    parts_separator = ", "
    part_separator = ":"
    extension_short_name = "subjectAltName"

    if hasattr(cert_or_req, 'get_extensions'):  # X509Req
        extensions = cert_or_req.get_extensions()
    else:  # X509
        extensions = [cert_or_req.get_extension(i)
                      for i in xrange(cert_or_req.get_extension_count())]

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
