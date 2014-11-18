The attic contains code and documentation about the letsencrypt protocol, an
alternative method for client webservers to request certificates from a server
CA.  Lets Encrypt does not plan to speak this protocol, though some of the
things here may be of future use.

Notes on this code:

The Chocolate project to implement sweet automatic encryption for webservers.

There are two portions to the Chocolate protocol.

letsencrypt/ contains code that can be run on any webserver (eventually,
email, XMPP and other SSL-securable servers too); it is used to automatically
request and install a CA-signed certificate for that server's public names.

server-ca/ contains a reference implementation for CAs to receive requests for
certs, set challenges for the requesting servers to prove that they really
control the names, and issue certificates.

Debian dependencies:

build deps:
swig
protobuf-compiler
python-dev

others:
gnutls-bin # for make cert requests
python-protobuf
python-dialog
hashcash
