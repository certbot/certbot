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
