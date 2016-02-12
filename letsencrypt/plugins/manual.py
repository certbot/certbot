"""Manual plugin."""
import os
import logging
import pipes
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)


class Authenticator(common.Plugin):
    """Manual Authenticator.

    This plugin requires user's manual intervention in setting up a HTTP
    server for solving http-01 challenges and thus does not need to be
    run as a privileged process. Alternatively shows instructions on how
    to use Python's built-in HTTP server.

    .. todo:: Support for `~.challenges.TLSSNI01`.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)
    hidden = True

    description = "Manually configure an HTTP server"

    MESSAGE_TEMPLATE = """\
Make sure your web server displays the following content at
{uri} before continuing:

{validation}

If you don't have HTTP server configured, you can run the following
command on the target server (as root):

{command}
"""

    # a disclaimer about your current IP being transmitted to Let's Encrypt's servers.
    IP_DISCLAIMER = """\
NOTE: The IP of this machine will be publicly logged as having requested this certificate. \
If you're running letsencrypt in manual mode on a machine that is not your server, \
please ensure you're okay with that.

Are you OK with your IP being logged?
"""

    # "cd /tmp/letsencrypt" makes sure user doesn't serve /root,
    # separate "public_html" ensures that cert.pem/key.pem are not
    # served and makes it more obvious that Python command will serve
    # anything recursively under the cwd

    CMD_TEMPLATE = """\
mkdir -p {root}/public_html/{achall.URI_ROOT_PATH}
cd {root}/public_html
printf "%s" {validation} > {achall.URI_ROOT_PATH}/{encoded_token}
# run only once per server:
$(command -v python2 || command -v python2.7 || command -v python2.6) -c \\
"import BaseHTTPServer, SimpleHTTPServer; \\
s = BaseHTTPServer.HTTPServer(('', {port}), SimpleHTTPServer.SimpleHTTPRequestHandler); \\
s.serve_forever()" """
    """Command template."""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self._root = (tempfile.mkdtemp() if self.conf("test-mode")
                      else "/tmp/letsencrypt")
        self._httpd = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("test-mode", action="store_true",
            help="Test mode. Executes the manual command in subprocess.")
        add("public-ip-logging-ok", action="store_true",
            help="Automatically allows public IP logging.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        if self.config.noninteractive_mode and not self.conf("test-mode"):
            raise errors.PluginError("Running manual mode non-interactively is not supported")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin requires user's manual intervention in setting "
                "up an HTTP server for solving http-01 challenges and thus "
                "does not need to be run as a privileged process. "
                "Alternatively shows instructions on how to use Python's "
                "built-in HTTP server.")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        # TODO: group achalls by the same socket.gethostbyname(_ex)
        # and prompt only once per server (one "echo -n" per domain)
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    @classmethod
    def _test_mode_busy_wait(cls, port):
        while True:
            time.sleep(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(("localhost", port))
            except socket.error:  # pragma: no cover
                pass
            else:
                break
            finally:
                sock.close()

    def _perform_single(self, achall):
        # same path for each challenge response would be easier for
        # users, but will not work if multiple domains point at the
        # same server: default command doesn't support virtual hosts
        response, validation = achall.response_and_validation()

        port = (response.port if self.config.http01_port is None
                else int(self.config.http01_port))
        command = self.CMD_TEMPLATE.format(
            root=self._root, achall=achall, response=response,
            # TODO(kuba): pipes still necessary?
            validation=pipes.quote(validation),
            encoded_token=achall.chall.encode("token"),
            port=port)
        if self.conf("test-mode"):
            logger.debug("Test mode. Executing the manual command: %s", command)
            # sh shipped with OS X does't support echo -n, but supports printf
            try:
                self._httpd = subprocess.Popen(
                    command,
                    # don't care about setting stdout and stderr,
                    # we're in test mode anyway
                    shell=True,
                    executable=None,
                    # "preexec_fn" is UNIX specific, but so is "command"
                    preexec_fn=os.setsid)
            except OSError as error:  # ValueError should not happen!
                logger.debug(
                    "Couldn't execute manual command: %s", error, exc_info=True)
                return False
            logger.debug("Manual command running as PID %s.", self._httpd.pid)
            # give it some time to bootstrap, before we try to verify
            # (cert generation in case of simpleHttpS might take time)
            self._test_mode_busy_wait(port)
            if self._httpd.poll() is not None:
                raise errors.Error("Couldn't execute manual command")
        else:
            if not self.conf("public-ip-logging-ok"):
                if not zope.component.getUtility(interfaces.IDisplay).yesno(
                        self.IP_DISCLAIMER, "Yes", "No",
                        cli_flag="--manual-public-ip-logging-ok"):
                    raise errors.PluginError("Must agree to IP logging to proceed")

            self._notify_and_wait(self.MESSAGE_TEMPLATE.format(
                validation=validation, response=response,
                uri=achall.chall.uri(achall.domain),
                command=command))

        if not response.simple_verify(
                achall.chall, achall.domain,
                achall.account_key.public_key(), self.config.http01_port):
            logger.warning("Self-verify of challenge failed.")

        return response

    def _notify_and_wait(self, message):  # pylint: disable=no-self-use
        # TODO: IDisplay wraps messages, breaking the command
        #answer = zope.component.getUtility(interfaces.IDisplay).notification(
        #    message=message, height=25, pause=True)
        sys.stdout.write(message)
        raw_input("Press ENTER to continue")

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        if self.conf("test-mode"):
            assert self._httpd is not None, (
                "cleanup() must be called after perform()")
            if self._httpd.poll() is None:
                logger.debug("Terminating manual command process")
                os.killpg(self._httpd.pid, signal.SIGTERM)
            else:
                logger.debug("Manual command process already terminated "
                             "with %s code", self._httpd.returncode)
            shutil.rmtree(self._root)
