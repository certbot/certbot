"""DNS-PERSIST-01 plugin"""
import logging
from textwrap import dedent
from typing import Callable, Iterable

from acme import challenges, messages
from acme.challenges import Challenge, ChallengeResponse
from certbot import achallenges, interfaces, reverter, util, errors
from certbot._internal import hooks
from certbot.compat import misc
from certbot.compat.os import environ
from certbot.configuration import NamespaceConfig
from certbot.plugins import common
from certbot.display import ops as display_ops
from certbot.display import util as display_util
from typing_extensions import override

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator):
    """dns-persist authenticator

    This plugin allows the user to perform automated challenges using ACME's dns-persist challenge
    type. This involves the creation of a single persistent TXT record per domain (or wildcard
    domain), which the user will either manually be guided through during the optional "setup" step,
    or can itself be automated through the use of hook scripts.

    """

    description: str = "Automatic certificate issuance via a persistent DNS TXT record"
    long_description: str = """
        Authenticate via a persistent DNS TXT record. Setting up this TXT record only needs to be
        done once using the --dns-persist-setup flag, and can either be done manually by the user,
        or automated through the use of setup and cleanup hook scripts. The setup hook script will
        be invoked once per ACME challenge, and will be provided environment variables which contain
        information about the challenge's corresponding domain and TXT record: $CERTBOT_IDENTIFIER
        will contain the domain or IP address being authenticated, while $CERTBOT_TXT_VALUE is the
        value of the TXT record. An additional cleanup script can be provided and can use the
        additional variable $CERTBOT_SETUP_SUCCEEDED, which will be 1 if all challenges succeeded,
        or 0 otherwise.
        """

    # Include the full stop at the end of the FQDN in the instructions below for the null
    # label of the DNS root, as stated in section 3.1 of RFC 1035. While not necessary
    # for most day to day usage of hostnames, when adding FQDNs to a DNS zone editor, this
    # full stop is often mandatory. Without a full stop, the entered name is often seen as
    # relative to the DNS zone origin, which could lead to entries for, e.g.:
    # _acme-challenge.example.com.example.com. For users unaware of this subtle detail,
    # including the trailing full stop in the DNS instructions below might avert this issue.
    _DNS_CHALLENGE_INSTRUCTIONS: str = dedent("""\
        Please deploy a DNS TXT record under the name:

        {domain}.

        with the following value:

        {validation}""")
    _SUBSEQUENT_DNS_CHALLENGE_INSTRUCTIONS: str = dedent("""\
        (This must be set up in addition to the previous challenges; do not remove, replace, or undo
        the previous challenge tasks yet. Note that you might be asked to create multiple distinct
        TXT records with the same name. This is permitted by DNS standards.)""")
    _FINAL_DNS_INSTRUCTIONS: str = dedent("""\
        Before continuing, verify the TXT record has been deployed. Depending on the DNS provider,
        this may take some time, from a few seconds to multiple minutes. You can check if it has
        finished deploying with aid of online tools, such as the Google Admin Toolbox:
        https://toolbox.googleapps.com/apps/dig/#TXT/{domain}. Look for one or more bolded line(s)
        below the line ';ANSWER'. It should show the value(s) you've just added.""")

    def __init__(self, config: NamespaceConfig, name: str) -> None:
        super().__init__(config, name)
        self.reverter: reverter.Reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()
        self.env: dict[achallenges.AnnotatedChallenge, dict[str, str]] = {}

    @classmethod
    @override
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        add('setup',
            help='Setup the DNS TXT records before performing the ACME challenges')
        add('setup-hook',
            help='Path or command to execute for the setup script')
        add('setup-cleanup-hook',
            help='Path or command to execute for the cleanup script')

    @override
    def prepare(self) -> None:
        setup_hook_provided = any(
            self.conf(arg) is not None for arg in ['setup-hook', 'setup-cleanup-hook']
        )
        if setup_hook_provided and not self.conf('setup'):
            raise errors.PluginError(("--dns-persist-setup-hook or "
                "--dns-persist-setup-cleanup-hook must be accompanied by "
                "--dns-persist-setup"))
        self._validate_hooks()

    def _validate_hooks(self) -> None:
        if self.config.validate_hooks:
            for name in ('setup-hook', 'setup-cleanup-hook'):
                hook = self.conf(name)
                if hook is not None:
                    hook_prefix = self.option_name(name)[:-len('-hook')]
                    hooks.validate_hook(hook, hook_prefix)

    @override
    def more_info(self) -> str:
        return (
            'This plugin allows the user to create a one-time DNS record that permits indefinite'
            'automated renewals, even for wildcard domains.')

    @override
    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        domains = [achall['domain'] for achall in failed_achalls]
        return dedent(f"""
            The Certificate Authority failed to verify the DNS TXT records for the following domains:
                {', '.join(domains)}
            Ensure that you created these in the correct location (for example, by running this
            command with the --dns-persist-setup flag), or try waiting longer for DNS propagation on
            the next attempt.""")

    @override
    def get_chall_pref(self, identifier: str) -> Iterable[type[Challenge]]:
        return [challenges.DNSPersist01]

    @override
    def perform(self, achalls: list[achallenges.AnnotatedChallenge]) -> list[ChallengeResponse]:
        persist_achalls: list[achallenges.DNSPersist] = []
        for achall in achalls:
            assert isinstance(achall, achallenges.DNSPersist), \
                'dns-persist plugin received incorrect challenge type'
            assert achall.identifier.typ == messages.IDENTIFIER_FQDN, \
                'dns-persist plugin challenge has invalid identifier'
            persist_achalls.append(achall)

        if self.conf('setup'):
            self._setup(persist_achalls)

        responses: list[ChallengeResponse] = []
        for achall in achalls:
            responses.append(achall.response())

        return responses

    def _setup(self, achalls: list[achallenges.DNSPersist]) -> None:
        for i, achall in enumerate(achalls):
            (domain, validation) = achall.get_dns_txt_record()
            if self.conf('setup-hook'):
                env = {
                    'CERTBOT_DOMAIN': domain,
                    'CERTBOT_VALIDATION': validation,
                }
                self._execute_hook('setup-hook', env)
            else:
                msg = self._DNS_CHALLENGE_INSTRUCTIONS.format(domain=domain, validation=validation)
                if i > 0:
                    msg += self._SUBSEQUENT_DNS_CHALLENGE_INSTRUCTIONS
                if i == len(achalls):
                    msg += self._FINAL_DNS_INSTRUCTIONS
                display_util.notification(msg, wrap=False, force_interactive=True)

    def cleanup(self, achalls: Iterable[achallenges.AnnotatedChallenge]) -> None:  # pylint: disable=missing-function-docstring
        if self.conf('setup') and self.conf('setup-cleanup-hook'):
            self._execute_hook('setup-cleanup-hook', {})
        self.reverter.recovery_routine()

    def _execute_hook(self, hook_name: str, env: dict[str, str]) -> tuple[str, str]:
        environ.update(env)
        returncode, err, out = misc.execute_command_status(
            self.option_name(hook_name), self.conf(hook_name),
            env=util.env_no_snap_for_external_calls()
        )

        display_ops.report_executed_command(
            f"Hook '--dns-persist-{hook_name}'", returncode, out, err)

        return err, out
