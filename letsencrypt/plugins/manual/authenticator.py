"""Manual plugin."""
import logging
import os
import sys

import requests
import zope.component
import zope.interface

from acme import challenges
from acme import jose

from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)


class ManualAuthenticator(common.Plugin):
    """Manual Authenticator.

    .. todo:: Support for `~.challenges.DVSNI`.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Manual Authenticator"

    MESSAGE_TEMPLATE = """\
Make sure your web server displays the following content at
{uri} before continuing:

{achall.token}

If you don't have HTTP server configured, you can run the following
command on the target server (as root):

{command}
"""

    HTTP_TEMPLATE = """\
mkdir -p {response.URI_ROOT_PATH}
echo -n {achall.token} > {response.URI_ROOT_PATH}/{response.path}
# run only once per server:
python -m SimpleHTTPServer 80"""
    """Non-TLS command template."""

    # https://www.piware.de/2011/01/creating-an-https-server-in-python/
    HTTPS_TEMPLATE = """\
mkdir -p {response.URI_ROOT_PATH}  # run only once per server
echo -n {achall.token} > {response.URI_ROOT_PATH}/{response.path}
# run only once per server:
openssl req -new -newkey rsa:4096 -subj "/" -days 1 -nodes -x509 -keyout key.pem -out cert.pem
python -c "import BaseHTTPServer, SimpleHTTPServer, ssl; \\
s = BaseHTTPServer.HTTPServer(('', 443), SimpleHTTPServer.SimpleHTTPRequestHandler); \\
s.socket = ssl.wrap_socket(s.socket, keyfile='key.pem', certfile='cert.pem'); \\
s.serve_forever()" """
    """TLS command template.

    According to the ACME specification, "the ACME server MUST ignore
    the certificate provided by the HTTPS server", so the first command
    generates temporary self-signed certificate. For the same reason
    ``requests.get`` in `_verify` sets ``verify=False``. Python HTTPS
    server command serves the ``token`` on all URIs.

    """

    def __init__(self, *args, **kwargs):
        super(ManualAuthenticator, self).__init__(*args, **kwargs)
        self.template = (self.HTTP_TEMPLATE if self.config.no_simple_http_tls
                         else self.HTTPS_TEMPLATE)

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return """\
This plugin requires user's manual intervention in setting up a HTTP
server for solving SimpleHTTP challenges and thus does not need to be
run as a privilidged process. Alternatively shows instructions on how
to use Python's built-in HTTP server and, in case of HTTPS, openssl
binary for temporary key/certificate generation.""".replace("\n", " ")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.SimpleHTTP]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        # TODO: group achalls by the same socket.gethostbyname(_ex)
        # and prompt only once per server (one "echo -n" per domain)
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    def _perform_single(self, achall):
        # same path for each challenge response would be easier for
        # users, but will not work if multiple domains point at the
        # same server: default command doesn't support virtual hosts
        response = challenges.SimpleHTTPResponse(
            path=jose.b64encode(os.urandom(18)),
            tls=(not self.config.no_simple_http_tls))
        assert response.good_path  # is encoded os.urandom(18) good?

        self._notify_and_wait(self.MESSAGE_TEMPLATE.format(
            achall=achall, response=response,
            uri=response.uri(achall.domain),
            command=self.template.format(achall=achall, response=response)))

        if self._verify(achall, response):
            return response
        else:
            return None

    def _notify_and_wait(self, message):  # pylint: disable=no-self-use
        # TODO: IDisplay wraps messages, breaking the command
        #answer = zope.component.getUtility(interfaces.IDisplay).notification(
        #    message=message, height=25, pause=True)
        sys.stdout.write(message)
        raw_input("Press ENTER to continue")

    def _verify(self, achall, chall_response):  # pylint: disable=no-self-use
        uri = chall_response.uri(achall.domain)
        logger.debug("Verifying %s...", uri)
        try:
            response = requests.get(uri, verify=False)
        except requests.exceptions.ConnectionError as error:
            logger.exception(error)
            return False

        ret = response.text == achall.token
        if not ret:
            logger.error("Unable to verify %s! Expected: %r, returned: %r.",
                         uri, achall.token, response.text)

        return ret

    def cleanup(self, achalls):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover
