"""Manual authenticator plugin"""
import zope.component
import zope.interface

from acme import challenges
from acme.magic_typing import Dict  # pylint: disable=unused-import, no-name-in-module

from certbot import achallenges  # pylint: disable=unused-import
from certbot import errors
from certbot import hooks
from certbot import interfaces
from certbot import reverter
from certbot.compat import os
from certbot.plugins import common


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
        'resource requested when performing an HTTP-01 challenge. An additional '
        'cleanup script can also be provided and can use the additional variable '
        '$CERTBOT_AUTH_OUTPUT which contains the stdout output from the auth script.')
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
    _SUBSEQUENT_CHALLENGE_INSTRUCTIONS = """
(This must be set up in addition to the previous challenges; do not remove,
replace, or undo the previous challenge tasks yet.)
"""
    _SUBSEQUENT_DNS_CHALLENGE_INSTRUCTIONS = """
(This must be set up in addition to the previous challenges; do not remove,
replace, or undo the previous challenge tasks yet. Note that you might be
asked to create multiple distinct TXT records with the same name. This is
permitted by DNS standards.)
"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()
        self.env = dict() \
        # type: Dict[achallenges.KeyAuthorizationAnnotatedChallenge, Dict[str, str]]
        self.subsequent_dns_challenge = False
        self.subsequent_any_challenge = False

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
        return [challenges.HTTP01, challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        self._verify_ip_logging_ok()
        if self.conf('auth-hook'):
            perform_achall = self._perform_achall_with_script
        else:
            perform_achall = self._perform_achall_manually

        responses = []
        for achall in achalls:
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
        os.environ.update(env)
        _, out = self._execute_hook('auth-hook')
        env['CERTBOT_AUTH_OUTPUT'] = out.strip()
        self.env[achall] = env

    def _perform_achall_manually(self, achall):
        validation = achall.validation(achall.account_key)
        if isinstance(achall.chall, challenges.HTTP01):
            msg = self._HTTP_INSTRUCTIONS.format(
                achall=achall, encoded_token=achall.chall.encode('token'),
                port=self.config.http01_port,
                uri=achall.chall.uri(achall.domain), validation=validation)
        else:
            assert isinstance(achall.chall, challenges.DNS01)
            msg = self._DNS_INSTRUCTIONS.format(
                domain=achall.validation_domain_name(achall.domain),
                validation=validation)
        if isinstance(achall.chall, challenges.DNS01):
            if self.subsequent_dns_challenge:
                # 2nd or later dns-01 challenge
                msg += self._SUBSEQUENT_DNS_CHALLENGE_INSTRUCTIONS
            self.subsequent_dns_challenge = True
        elif self.subsequent_any_challenge:
            # 2nd or later challenge of another type
            msg += self._SUBSEQUENT_CHALLENGE_INSTRUCTIONS
        display = zope.component.getUtility(interfaces.IDisplay)
        display.notification(msg, wrap=False, force_interactive=True)
        self.subsequent_any_challenge = True

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        if self.conf('cleanup-hook'):
            for achall in achalls:
                env = self.env.pop(achall)
                if 'CERTBOT_TOKEN' not in env:
                    os.environ.pop('CERTBOT_TOKEN', None)
                os.environ.update(env)
                self._execute_hook('cleanup-hook')
        self.reverter.recovery_routine()

    def _execute_hook(self, hook_name):
        return hooks.execute(self.option_name(hook_name), self.conf(hook_name))
