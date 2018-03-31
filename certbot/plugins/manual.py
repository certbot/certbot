"""Manual authenticator plugin"""
import os

import zope.component
import zope.interface

from acme import challenges

from certbot import interfaces
from certbot import errors
from certbot import hooks
from certbot import reverter
from certbot.plugins import common


class ManualTlsSni01(common.TLSSNI01):
    """TLS-SNI-01 authenticator for the Manual plugin

    :ivar configurator: Authenticator object
    :type configurator: :class:`~certbot.plugins.manual.Authenticator`

    :ivar list achalls: Annotated
        class:`~certbot.achallenges.KeyAuthorizationAnnotatedChallenge`
        challenges

    :param list indices: Meant to hold indices of challenges in a
        larger array. NginxTlsSni01 is capable of solving many challenges
        at once which causes an indexing issue within NginxConfigurator
        who must return all responses in order.  Imagine NginxConfigurator
        maintaining state about where all of the http-01 Challenges,
        TLS-SNI-01 Challenges belong in the response array.  This is an
        optional utility.

    :param str challenge_conf: location of the challenge config file
    """

    def perform(self):
        """Create the SSL certificates and private keys"""

        for achall in self.achalls:
            self._setup_challenge_cert(achall)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Manual authenticator

    This plugin allows the user to perform the domain validation
    challenge(s) themselves. This either be done manually by the user or
    through shell scripts provided to Certbot.

    """

    description = 'Manual configuration or run your own shell scripts'
    hidden = True
    long_description = (
        'Authenticate through manual configuration or custom shell scripts. '
        'When using shell scripts, an authenticator script must be provided. '
        'The environment variables available to this script depend on the '
        'type of challenge. $CERTBOT_DOMAIN will always contain the domain '
        'being authenticated. For HTTP-01 and DNS-01, $CERTBOT_VALIDATION '
        'is the validation string, and $CERTBOT_TOKEN is the filename of the '
        'resource requested when performing an HTTP-01 challenge. When '
        'performing a TLS-SNI-01 challenge, $CERTBOT_SNI_DOMAIN will contain '
        'the SNI name for which the ACME server expects to be presented with '
        'the self-signed certificate located at $CERTBOT_CERT_PATH. The '
        'secret key needed to complete the TLS handshake is located at '
        '$CERTBOT_KEY_PATH. An additional cleanup script can also be '
        'provided and can use the additional variable $CERTBOT_AUTH_OUTPUT '
        'which contains the stdout output from the auth script.')
    _DNS_INSTRUCTIONS = """\
Please deploy a DNS TXT record under the name
{domain} with the following value:

{validation}

Before continuing, verify the record is deployed."""
    _HTTP_INSTRUCTIONS = """\
Create a file containing just this data:

{validation}

And make it available on your web server at this URL:

{uri}
"""
    _TLSSNI_INSTRUCTIONS = """\
Configure the service listening on port {port} to present the certificate
{cert}
using the secret key
{key}
when it receives a TLS ClientHello with the SNI extension set to
{sni_domain}
"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()
        self.env = dict()
        self.tls_sni_01 = None

    @classmethod
    def add_parser_arguments(cls, add):
        add('auth-hook',
            help='Path or command to execute for the authentication script')
        add('cleanup-hook',
            help='Path or command to execute for the cleanup script')
        add('public-ip-logging-ok', action='store_true',
            help='Automatically allows public IP logging (default: Ask)')

    def prepare(self):  # pylint: disable=missing-docstring
        if self.config.noninteractive_mode and not self.conf('auth-hook'):
            raise errors.PluginError(
                'An authentication script must be provided with --{0} when '
                'using the manual plugin non-interactively.'.format(
                    self.option_name('auth-hook')))
        self._validate_hooks()

    def _validate_hooks(self):
        if self.config.validate_hooks:
            for name in ('auth-hook', 'cleanup-hook'):
                hook = self.conf(name)
                if hook is not None:
                    hook_prefix = self.option_name(name)[:-len('-hook')]
                    hooks.validate_hook(hook, hook_prefix)

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            'This plugin allows the user to customize setup for domain '
            'validation challenges either through shell scripts provided by '
            'the user or by performing the setup manually.')

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01, challenges.DNS01, challenges.TLSSNI01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        self._verify_ip_logging_ok()
        if self.conf('auth-hook'):
            perform_achall = self._perform_achall_with_script
        else:
            perform_achall = self._perform_achall_manually

        responses = []
        for achall in achalls:
            if isinstance(achall.chall, challenges.TLSSNI01):
                # Make a new ManualTlsSni01 instance for each challenge
                # because the manual plugin deals with one challenge at a time.
                self.tls_sni_01 = ManualTlsSni01(self)
                self.tls_sni_01.add_chall(achall)
                self.tls_sni_01.perform()
            perform_achall(achall)
            responses.append(achall.response(achall.account_key))
        return responses

    def _verify_ip_logging_ok(self):
        if not self.conf('public-ip-logging-ok'):
            cli_flag = '--{0}'.format(self.option_name('public-ip-logging-ok'))
            msg = ('NOTE: The IP of this machine will be publicly logged as '
                   "having requested this certificate. If you're running "
                   'certbot in manual mode on a machine that is not your '
                   "server, please ensure you're okay with that.\n\n"
                   'Are you OK with your IP being logged?')
            display = zope.component.getUtility(interfaces.IDisplay)
            if display.yesno(msg, cli_flag=cli_flag, force_interactive=True):
                setattr(self.config, self.dest('public-ip-logging-ok'), True)
            else:
                raise errors.PluginError('Must agree to IP logging to proceed')

    def _perform_achall_with_script(self, achall):
        env = dict(CERTBOT_DOMAIN=achall.domain,
                   CERTBOT_VALIDATION=achall.validation(achall.account_key))
        if isinstance(achall.chall, challenges.HTTP01):
            env['CERTBOT_TOKEN'] = achall.chall.encode('token')
        else:
            os.environ.pop('CERTBOT_TOKEN', None)
        if isinstance(achall.chall, challenges.TLSSNI01):
            env['CERTBOT_CERT_PATH'] = self.tls_sni_01.get_cert_path(achall)
            env['CERTBOT_KEY_PATH'] = self.tls_sni_01.get_key_path(achall)
            env['CERTBOT_SNI_DOMAIN'] = self.tls_sni_01.get_z_domain(achall)
            os.environ.pop('CERTBOT_VALIDATION', None)
            env.pop('CERTBOT_VALIDATION')
        else:
            os.environ.pop('CERTBOT_CERT_PATH', None)
            os.environ.pop('CERTBOT_KEY_PATH', None)
            os.environ.pop('CERTBOT_SNI_DOMAIN', None)
        os.environ.update(env)
        _, out = hooks.execute(self.conf('auth-hook'))
        env['CERTBOT_AUTH_OUTPUT'] = out.strip()
        self.env[achall] = env

    def _perform_achall_manually(self, achall):
        validation = achall.validation(achall.account_key)
        if isinstance(achall.chall, challenges.HTTP01):
            msg = self._HTTP_INSTRUCTIONS.format(
                achall=achall, encoded_token=achall.chall.encode('token'),
                port=self.config.http01_port,
                uri=achall.chall.uri(achall.domain), validation=validation)
        elif isinstance(achall.chall, challenges.DNS01):
            msg = self._DNS_INSTRUCTIONS.format(
                domain=achall.validation_domain_name(achall.domain),
                validation=validation)
        else:
            assert isinstance(achall.chall, challenges.TLSSNI01)
            msg = self._TLSSNI_INSTRUCTIONS.format(
                cert=self.tls_sni_01.get_cert_path(achall),
                key=self.tls_sni_01.get_key_path(achall),
                port=self.config.tls_sni_01_port,
                sni_domain=self.tls_sni_01.get_z_domain(achall))
        display = zope.component.getUtility(interfaces.IDisplay)
        display.notification(msg, wrap=False, force_interactive=True)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self.conf('cleanup-hook'):
            for achall in achalls:
                env = self.env.pop(achall)
                if 'CERTBOT_TOKEN' not in env:
                    os.environ.pop('CERTBOT_TOKEN', None)
                os.environ.update(env)
                hooks.execute(self.conf('cleanup-hook'))
        self.reverter.recovery_routine()
