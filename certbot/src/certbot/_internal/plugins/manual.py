"""Manual authenticator plugin"""
import logging
from typing import Any
from typing import Callable
from typing import Iterable

from acme import challenges, messages
from certbot import achallenges
from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot import util
from certbot._internal import hooks
from certbot._internal.cli import cli_constants
from certbot.compat import misc
from certbot.compat import os
from certbot.display import ops as display_ops
from certbot.display import util as display_util
from certbot.plugins import common

logger = logging.getLogger(__name__)


class Authenticator(common.Plugin, interfaces.Authenticator):
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
        '$CERTBOT_AUTH_OUTPUT which contains the stdout output from the auth script. '
        'For both authenticator and cleanup script, on HTTP-01 and DNS-01 challenges, '
        '$CERTBOT_REMAINING_CHALLENGES will be equal to the number of challenges that '
        'remain after the current one, and $CERTBOT_ALL_DOMAINS contains a comma-separated '
        'list of all domains that are challenged for the current certificate.')
    # Include the full stop at the end of the FQDN in the instructions below for the null
    # label of the DNS root, as stated in section 3.1 of RFC 1035. While not necessary
    # for most day to day usage of hostnames, when adding FQDNs to a DNS zone editor, this
    # full stop is often mandatory. Without a full stop, the entered name is often seen as
    # relative to the DNS zone origin, which could lead to entries for, e.g.:
    # _acme-challenge.example.com.example.com. For users unaware of this subtle detail,
    # including the trailing full stop in the DNS instructions below might avert this issue.
    _DNS_INSTRUCTIONS = """\
Please deploy a DNS TXT record under the name:

{domain}.

with the following value:

{validation}
"""
    _DNS_VERIFY_INSTRUCTIONS = """
Before continuing, verify the TXT record has been deployed. Depending on the DNS
provider, this may take some time, from a few seconds to multiple minutes. You can
check if it has finished deploying with aid of online tools, such as the Google
Admin Toolbox: https://toolbox.googleapps.com/apps/dig/#TXT/{domain}.
Look for one or more bolded line(s) below the line ';ANSWER'. It should show the
value(s) you've just added.
"""
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

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()
        self.env: dict[achallenges.AnnotatedChallenge, dict[str, str]] = {}
        self.subsequent_dns_challenge = False
        self.subsequent_any_challenge = False

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        add('auth-hook',
            help='Path or command to execute for the authentication script')
        add('cleanup-hook',
            help='Path or command to execute for the cleanup script')

    def prepare(self) -> None:  # pylint: disable=missing-function-docstring
        if self.config.noninteractive_mode and not self.conf('auth-hook'):
            raise errors.PluginError(
                'An authentication script must be provided with --{0} when '
                'using the manual plugin non-interactively.'.format(
                    self.option_name('auth-hook')))
        self._validate_hooks()

    def _validate_hooks(self) -> None:
        if self.config.validate_hooks:
            for name in ('auth-hook', 'cleanup-hook'):
                hook = self.conf(name)
                if hook is not None:
                    hook_prefix = self.option_name(name)[:-len('-hook')]
                    hooks.validate_hook(hook, hook_prefix)

    def more_info(self) -> str:  # pylint: disable=missing-function-docstring
        return (
            'This plugin allows the user to customize setup for domain '
            'validation challenges either through shell scripts provided by '
            'the user or by performing the setup manually.')

    def auth_hint(self, failed_achalls: Iterable[achallenges.AnnotatedChallenge]) -> str:
        def has_chall(cls: type[challenges.Challenge]) -> bool:
            return any(isinstance(achall.chall, cls) for achall in failed_achalls)

        has_dns = has_chall(challenges.DNS01)
        resource_names = {
            challenges.DNS01: 'DNS TXT records',
            challenges.HTTP01: 'challenge files',
        }
        resources = ' and '.join(sorted([v for k, v in resource_names.items() if has_chall(k)]))

        if self.conf('auth-hook'):
            return (
                'The Certificate Authority failed to verify the {resources} created by the '
                '--manual-auth-hook. Ensure that this hook is functioning correctly{dns_hint}. '
                'Refer to "{certbot} --help manual" and the Certbot User Guide.'
                .format(
                    certbot=cli_constants.cli_command,
                    resources=resources,
                    dns_hint=(
                        ' and that it waits a sufficient duration of time for DNS propagation'
                    ) if has_dns else ''
                )
            )
        else:
            return (
                'The Certificate Authority failed to verify the manually created {resources}. '
                'Ensure that you created these in the correct location{dns_hint}.'
                .format(
                    resources=resources,
                    dns_hint=(
                        ', or try waiting longer for DNS propagation on the next attempt'
                     ) if has_dns else ''
                )
            )

    def get_chall_pref(self, domain: str) -> Iterable[type[challenges.Challenge]]:
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenges.HTTP01, challenges.DNS01]

    def perform(self, achalls: list[achallenges.AnnotatedChallenge]
                ) -> list[challenges.ChallengeResponse]:  # pylint: disable=missing-function-docstring
        responses = []
        last_dns_achall = 0
        for i, achall in enumerate(achalls):
            if isinstance(achall.chall, challenges.DNS01):
                last_dns_achall = i
        for i, achall in enumerate(achalls):
            if self.conf('auth-hook'):
                self._perform_achall_with_script(achall, achalls)
            else:
                self._perform_achall_manually(achall, i == last_dns_achall)
            responses.append(achall.response(achall.account_key))
        return responses

    def _perform_achall_with_script(self, achall: achallenges.AnnotatedChallenge,
                                    achalls: list[achallenges.AnnotatedChallenge]) -> None:
        if not achall.identifier.typ == messages.IDENTIFIER_FQDN:
            raise errors.ConfigurationError("non-FQDN identifiers not yet supported")
        domain = achall.identifier.value
        env = {
            "CERTBOT_DOMAIN": domain,
            "CERTBOT_VALIDATION": achall.validation(achall.account_key),
            "CERTBOT_ALL_DOMAINS": ','.join(one_achall.identifier.value for one_achall in achalls),
            "CERTBOT_REMAINING_CHALLENGES": str(len(achalls) - achalls.index(achall) - 1),
        }
        if isinstance(achall.chall, challenges.HTTP01):
            env['CERTBOT_TOKEN'] = achall.chall.encode('token')
        else:
            os.environ.pop('CERTBOT_TOKEN', None)
        os.environ.update(env)
        _, out = self._execute_hook('auth-hook', domain)
        env['CERTBOT_AUTH_OUTPUT'] = out.strip()
        self.env[achall] = env

    def _perform_achall_manually(self, achall: achallenges.AnnotatedChallenge,
                                 last_dns_achall: bool = False) -> None:
        if not achall.identifier.typ == messages.IDENTIFIER_FQDN:
            raise errors.ConfigurationError("non-FQDN identifiers not yet supported")
        domain = achall.identifier.value
        validation = achall.validation(achall.account_key)
        if isinstance(achall.chall, challenges.HTTP01):
            msg = self._HTTP_INSTRUCTIONS.format(
                achall=achall, encoded_token=achall.chall.encode('token'),
                port=self.config.http01_port,
                uri=achall.chall.uri(domain), validation=validation)
        else:
            assert isinstance(achall.chall, challenges.DNS01)
            msg = self._DNS_INSTRUCTIONS.format(
                domain=achall.validation_domain_name(domain),
                validation=validation)
        if isinstance(achall.chall, challenges.DNS01):
            if self.subsequent_dns_challenge:
                # 2nd or later dns-01 challenge
                msg += self._SUBSEQUENT_DNS_CHALLENGE_INSTRUCTIONS
            elif self.subsequent_any_challenge:
                # 1st dns-01 challenge, but 2nd or later *any* challenge, so
                # instruct user not to remove any previous http-01 challenge
                msg += self._SUBSEQUENT_CHALLENGE_INSTRUCTIONS
            self.subsequent_dns_challenge = True
            if last_dns_achall:
                # last dns-01 challenge
                msg += self._DNS_VERIFY_INSTRUCTIONS.format(
                    domain=achall.validation_domain_name(domain))
        elif self.subsequent_any_challenge:
            # 2nd or later challenge of another type
            msg += self._SUBSEQUENT_CHALLENGE_INSTRUCTIONS
        display_util.notification(msg, wrap=False, force_interactive=True)
        self.subsequent_any_challenge = True

    def cleanup(self, achalls: Iterable[achallenges.AnnotatedChallenge]) -> None:  # pylint: disable=missing-function-docstring
        if self.conf('cleanup-hook'):
            for achall in achalls:
                env = self.env.pop(achall)
                if 'CERTBOT_TOKEN' not in env:
                    os.environ.pop('CERTBOT_TOKEN', None)
                os.environ.update(env)
                self._execute_hook('cleanup-hook', achall.identifier.value)
        self.reverter.recovery_routine()

    def _execute_hook(self, hook_name: str, achall_domain: str) -> tuple[str, str]:
        returncode, err, out = misc.execute_command_status(
            self.option_name(hook_name), self.conf(hook_name),
            env=util.env_no_snap_for_external_calls()
        )

        display_ops.report_executed_command(
            f"Hook '--manual-{hook_name}' for {achall_domain}", returncode, out, err)

        return err, out
