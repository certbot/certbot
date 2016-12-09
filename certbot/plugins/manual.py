"""Manual authenticator plugin"""
import os

import zope.component
import zope.interface

from acme import challenges

from certbot import interfaces
from certbot import errors
from certbot import hooks
from certbot.plugins import common


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Manual authenticator

    This plugin allows the user to perform the domain validation
    challenge(s) themselves. This can be done either be done manually
    by the user or through shell scripts provided to Certbot.

    """

    description = 'Manual configuration or run your own shell scripts'
    hidden = True
    long_description = (
        'Authenticate through manual configuration or custom shell scripts. '
        'When using shell scripts, an authenticator script must be provided. '
        'The environment variables available to this script are '
        '$CERTBOT_DOMAIN which contains the domain being authenticated, '
        '$CERTBOT_VALIDATION which is the validation string, and '
        '$CERTBOT_TOKEN which is the filename of the resource requested when '
        'performing an HTTP-01 challenge. An additional cleanup script can '
        'also be provided and can use the additional variable '
        '$CERTBOT_AUTH_OUTPUT which contains the stdout output from the auth '
        'script.')
    _DNS_INSTRUCTIONS = """\
Please deploy a DNS TXT record under the name
{domain} with the following value:

{validation}

Once this is deployed,
"""
    _HTTP_INSTRUCTIONS = """\
Make sure your web server displays the following content at
{uri} before continuing:

{validation}

If you don't have HTTP server configured, you can run the following
command on the target server (as root):

mkdir -p /tmp/certbot/public_html/{achall.URI_ROOT_PATH}
cd /tmp/certbot/public_html
printf "%s" {validation} > {achall.URI_ROOT_PATH}/{encoded_token}
# run only once per server:
$(command -v python2 || command -v python2.7 || command -v python2.6) -c \\
"import BaseHTTPServer, SimpleHTTPServer; \\
s = BaseHTTPServer.HTTPServer(('', {port}), SimpleHTTPServer.SimpleHTTPRequestHandler); \\
s.serve_forever()"
"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.env = dict()

    @classmethod
    def add_parser_arguments(cls, add):
        add('auth-script',
            help='Path or command to execute for the authentication script')
        add('cleanup-script',
            help='Path or command to execute for the cleanup script')
        add('public-ip-logging-ok', action='store_true',
            help='Automatically allows public IP logging')

    def prepare(self):  # pylint: disable=missing-docstring
        if self.config.noninteractive_mode and not self.conf('auth-script'):
            raise errors.PluginError(
                'An authentication script must be provided with --{0} when '
                'using the manual plugin non-interactively.'.format(
                    self.option_name('auth-script')))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            'This plugin allows the user to customize setup for domain '
            'validation challenges either through shell scripts provided by '
            'the user or by performing the setup manually.')

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01, challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        self._verify_ip_logging_ok()

        responses = []
        for achall in achalls:
            response, validation = achall.response_and_validation()
            if self.conf('auth-script'):
                self._perform_achall_with_script(achall, validation)
            else:
                self._perform_achall_manually(achall, response, validation)
            responses.append(response)
        return responses

    def _verify_ip_logging_ok(self):
        if not self.conf('public-ip-logging-ok'):
            cli_flag = self.option_name('public-ip-logging-ok')
            msg = ('NOTE: The IP of this machine will be publicly logged as '
                   "having requested this certificate. If you're running "
                   'certbot in manual mode on a machine that is not your '
                   "server, please ensure you're okay with that.\n\n"
                   'Are you OK with your IP being logged?')
            display = zope.component.getUtility(interfaces.IDisplay)
            if display.yesno(msg, cli_flag=cli_flag):
                setattr(self.config, self.dest('public-ip-logging-ok'), True)
            else:
                raise errors.PluginError('Must agree to IP logging to proceed')

    def _perform_achall_with_script(self, achall, validation):
        env = dict(CERTBOT_DOMAIN=achall.domain, CERTBOT_VALIDATION=validation)
        if isinstance(achall.chall, challenges.HTTP01):
            env['CERTBOT_TOKEN'] = achall.chall.encode("token")
        os.environ.update(env)
        _, out = hooks.execute(self.conf('auth-script'))
        env['CERTBOT_AUTH_OUTPUT'] = out.strip()
        self.env[achall.domain] = env

    def _perform_achall_manually(self, achall, response, validation):
        if isinstance(achall.chall, challenges.HTTP01):
            if self.config.http01_port is None:
                port = response.port
            else:
                port = self.config.http01_port
            msg = self._HTTP_INSTRUCTIONS.format(
                achall=achall, encoded_token=achall.chall.encode('token'),
                response=response, port=port, uri=achall.uri(achall.domain),
                validation=validation)
        else:
            assert isinstance(achall.chall, challenges.DNS01)
            msg = self._DNS_INSTRUCTIONS.format(
                domain=achall.validation_domain_name(achall.domain),
                response=response, validation=validation)
        display = zope.component.getUtility(interfaces.IDisplay)
        display.notification(msg, wrap=False)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self.conf('cleanup-script'):
            for achall in achalls:
                os.environ.update(self.env[achall.domain])
                hooks.execute(self.conf('cleanup-script'))
