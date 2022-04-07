"""ACME AuthHandler."""
import datetime
import logging
import time
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Type

import josepy
from requests.models import Response

from acme import challenges
from acme import client
from acme import errors as acme_errors
from acme import messages
from certbot import achallenges
from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot._internal import error_handler
from certbot._internal.account import Account
from certbot.display import util as display_util
from certbot.plugins import common as plugin_common

logger = logging.getLogger(__name__)


class AuthHandler:
    """ACME Authorization Handler for a client.

    :ivar auth: Authenticator capable of solving
        :class:`~acme.challenges.Challenge` types
    :type auth: certbot.interfaces.Authenticator

    :ivar acme.client.BackwardsCompatibleClientV2 acme_client: ACME client API.

    :ivar account: Client's Account
    :type account: :class:`certbot._internal.account.Account`

    :ivar list pref_challs: sorted user specified preferred challenges
        type strings with the most preferred challenge listed first

    """
    def __init__(self, auth: interfaces.Authenticator, acme_client: Optional[client.ClientV2],
                 account: Optional[Account], pref_challs: List[str]) -> None:
        self.auth = auth
        self.acme = acme_client

        self.account = account
        self.pref_challs = pref_challs

    def handle_authorizations(self, orderr: messages.OrderResource,
                              config: configuration.NamespaceConfig, best_effort: bool = False,
                              max_retries: int = 30) -> List[messages.AuthorizationResource]:
        """
        Retrieve all authorizations, perform all challenges required to validate
        these authorizations, then poll and wait for the authorization to be checked.
        :param acme.messages.OrderResource orderr: must have authorizations filled in
        :param certbot.configuration.NamespaceConfig config: current Certbot configuration
        :param bool best_effort: if True, not all authorizations need to be validated (eg. renew)
        :param int max_retries: maximum number of retries to poll authorizations
        :returns: list of all validated authorizations
        :rtype: List

        :raises .AuthorizationError: If unable to retrieve all authorizations
        """
        authzrs = orderr.authorizations[:]
        if not authzrs:
            raise errors.AuthorizationError('No authorization to handle.')
        if not self.acme:
            raise errors.Error("No ACME client defined, authorizations cannot be handled.")

        # Retrieve challenges that need to be performed to validate authorizations.
        achalls = self._choose_challenges(authzrs)
        if not achalls:
            return authzrs

        # Starting now, challenges will be cleaned at the end no matter what.
        with error_handler.ExitHandler(self._cleanup_challenges, achalls):
            # To begin, let's ask the authenticator plugin to perform all challenges.
            try:
                resps = self.auth.perform(achalls)

                # If debug is on, wait for user input before starting the verification process.
                if config.debug_challenges:
                    display_util.notification(
                        'Challenges loaded. Press continue to submit to CA.\n' +
                        self._debug_challenges_msg(achalls, config), pause=True)
            except errors.AuthorizationError as error:
                logger.critical('Failure in setting up challenges.')
                logger.info('Attempting to clean up outstanding challenges...')
                raise error
            # All challenges should have been processed by the authenticator.
            assert len(resps) == len(achalls), 'Some challenges have not been performed.'

            # Inform the ACME CA server that challenges are available for validation.
            for achall, resp in zip(achalls, resps):
                self.acme.answer_challenge(achall.challb, resp)

            # Wait for authorizations to be checked.
            logger.info('Waiting for verification...')
            self._poll_authorizations(authzrs, max_retries, best_effort)

            # Keep validated authorizations only. If there is none, no certificate can be issued.
            authzrs_validated = [authzr for authzr in authzrs
                                 if authzr.body.status == messages.STATUS_VALID]
            if not authzrs_validated:
                raise errors.AuthorizationError('All challenges have failed.')

            return authzrs_validated

        raise errors.Error("An unexpected error occurred while handling the authorizations.")

    def deactivate_valid_authorizations(self, orderr: messages.OrderResource) -> Tuple[List, List]:
        """
        Deactivate all `valid` authorizations in the order, so that they cannot be re-used
        in subsequent orders.
        :param messages.OrderResource orderr: must have authorizations filled in
        :returns: tuple of list of successfully deactivated authorizations, and
                  list of unsuccessfully deactivated authorizations.
        :rtype: tuple
        """
        if not self.acme:
            raise errors.Error("No ACME client defined, cannot deactivate valid authorizations.")

        to_deactivate = [authzr for authzr in orderr.authorizations
                         if authzr.body.status == messages.STATUS_VALID]
        deactivated = []
        failed = []

        for authzr in to_deactivate:
            try:
                authzr = self.acme.deactivate_authorization(authzr)
                deactivated.append(authzr)
            except acme_errors.Error as e:
                failed.append(authzr)
                logger.debug('Failed to deactivate authorization %s: %s', authzr.uri, e)

        return (deactivated, failed)

    def _poll_authorizations(self, authzrs: List[messages.AuthorizationResource], max_retries: int,
                             best_effort: bool) -> None:
        """
        Poll the ACME CA server, to wait for confirmation that authorizations have their challenges
        all verified. The poll may occur several times, until all authorizations are checked
        (valid or invalid), or after a maximum of retries.
        """
        if not self.acme:
            raise errors.Error("No ACME client defined, cannot poll authorizations.")

        authzrs_to_check: Dict[int, Tuple[messages.AuthorizationResource,
                                          Optional[Response]]] = {index: (authzr, None)
                            for index, authzr in enumerate(authzrs)}
        authzrs_failed_to_report = []
        # Give an initial second to the ACME CA server to check the authorizations
        sleep_seconds: float = 1
        for _ in range(max_retries):
            # Wait for appropriate time (from Retry-After, initial wait, or no wait)
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
            # Poll all updated authorizations.
            authzrs_to_check = {index: self.acme.poll(authzr) for index, (authzr, _)
                                in authzrs_to_check.items()}
            # Update the original list of authzr with the updated authzrs from server.
            for index, (authzr, _) in authzrs_to_check.items():
                authzrs[index] = authzr

            # Gather failed authorizations
            authzrs_failed = [authzr for authzr, _ in authzrs_to_check.values()
                              if authzr.body.status == messages.STATUS_INVALID]
            for authzr_failed in authzrs_failed:
                logger.info('Challenge failed for domain %s',
                               authzr_failed.body.identifier.value)
            # Accumulating all failed authzrs to build a consolidated report
            # on them at the end of the polling.
            authzrs_failed_to_report.extend(authzrs_failed)

            # Extract out the authorization already checked for next poll iteration.
            # Poll may stop here because there is no pending authorizations anymore.
            authzrs_to_check = {index: (authzr, resp) for index, (authzr, resp)
                                in authzrs_to_check.items()
                                if authzr.body.status == messages.STATUS_PENDING}
            if not authzrs_to_check:
                # Polling process is finished, we can leave the loop
                break

            # Be merciful with the ACME server CA, check the Retry-After header returned,
            # and wait this time before polling again in next loop iteration.
            # From all the pending authorizations, we take the greatest Retry-After value
            # to avoid polling an authorization before its relevant Retry-After value.
            # (by construction resp cannot be None at that time, but mypy do not know it).
            retry_after = max(self.acme.retry_after(resp, 3)
                              for _, resp in authzrs_to_check.values()
                              if resp is not None)
            sleep_seconds = (retry_after - datetime.datetime.now()).total_seconds()

        # In case of failed authzrs, create a report to the user.
        if authzrs_failed_to_report:
            self._report_failed_authzrs(authzrs_failed_to_report)
            if not best_effort:
                # Without best effort, having failed authzrs is critical and fail the process.
                raise errors.AuthorizationError('Some challenges have failed.')

        if authzrs_to_check:
            # Here authzrs_to_check is still not empty, meaning we exceeded the max polling attempt.
            raise errors.AuthorizationError('All authorizations were not finalized by the CA.')

    def _choose_challenges(self, authzrs: Iterable[messages.AuthorizationResource]
                           ) -> List[achallenges.AnnotatedChallenge]:
        """
        Retrieve necessary and pending challenges to satisfy server.
        NB: Necessary and already validated challenges are not retrieved,
        as they can be reused for a certificate issuance.
        """
        if not self.acme:
            raise errors.Error("No ACME client defined, cannot choose the challenges.")

        pending_authzrs = [authzr for authzr in authzrs
                           if authzr.body.status != messages.STATUS_VALID]
        achalls: List[achallenges.AnnotatedChallenge] = []
        if pending_authzrs:
            logger.info("Performing the following challenges:")
        for authzr in pending_authzrs:
            authzr_challenges = authzr.body.challenges
            if self.acme.acme_version == 1:
                combinations = authzr.body.combinations
            else:
                combinations = tuple((i,) for i in range(len(authzr_challenges)))

            path = gen_challenge_path(
                authzr_challenges,
                self._get_chall_pref(authzr.body.identifier.value),
                combinations)

            achalls.extend(self._challenge_factory(authzr, path))

        return achalls

    def _get_chall_pref(self, domain: str) -> List[Type[challenges.Challenge]]:
        """Return list of challenge preferences.

        :param str domain: domain for which you are requesting preferences

        """
        chall_prefs = []
        # Make sure to make a copy...
        plugin_pref = self.auth.get_chall_pref(domain)
        if self.pref_challs:
            plugin_pref_types = {chall.typ for chall in plugin_pref}
            for typ in self.pref_challs:
                if typ in plugin_pref_types:
                    chall_prefs.append(challenges.Challenge.TYPES[typ])
            if chall_prefs:
                return chall_prefs
            raise errors.AuthorizationError(
                "None of the preferred challenges "
                "are supported by the selected plugin")
        chall_prefs.extend(plugin_pref)
        return chall_prefs

    def _cleanup_challenges(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        """Cleanup challenges.

        :param achalls: annotated challenges to cleanup
        :type achalls: `list` of :class:`certbot.achallenges.AnnotatedChallenge`

        """
        logger.info("Cleaning up challenges")
        self.auth.cleanup(achalls)

    def _challenge_factory(self, authzr: messages.AuthorizationResource,
                           path: Sequence[int]) -> List[achallenges.AnnotatedChallenge]:
        """Construct Namedtuple Challenges

        :param messages.AuthorizationResource authzr: authorization

        :param list path: List of indices from `challenges`.

        :returns: achalls, list of challenge type
            :class:`certbot.achallenges.AnnotatedChallenge`
        :rtype: list

        :raises .errors.Error: if challenge type is not recognized

        """
        if not self.account:
            raise errors.Error("Account is not set.")
        achalls = []

        for index in path:
            challb = authzr.body.challenges[index]
            achalls.append(challb_to_achall(
                challb, self.account.key, authzr.body.identifier.value))

        return achalls

    def _report_failed_authzrs(self, failed_authzrs: List[messages.AuthorizationResource]) -> None:
        """Notifies the user about failed authorizations."""
        if not self.account:
            raise errors.Error("Account is not set.")
        problems: Dict[str, List[achallenges.AnnotatedChallenge]] = {}
        failed_achalls = [challb_to_achall(challb, self.account.key, authzr.body.identifier.value)
                        for authzr in failed_authzrs for challb in authzr.body.challenges
                        if challb.error]

        for achall in failed_achalls:
            problems.setdefault(achall.error.typ, []).append(achall)

        msg = ["\nCertbot failed to authenticate some domains "
               f"(authenticator: {self.auth.name})."
               " The Certificate Authority reported these problems:"]

        for _, achalls in sorted(problems.items(), key=lambda item: item[0]):
            msg.append(_generate_failed_chall_msg(achalls))

        # auth_hint will only be called on authenticators that subclass
        # plugin_common.Plugin. Refer to comment on that function.
        if failed_achalls and isinstance(self.auth, plugin_common.Plugin):
            msg.append(f"\nHint: {self.auth.auth_hint(failed_achalls)}\n")

        display_util.notify("".join(msg))

    def _debug_challenges_msg(self, achalls: List[achallenges.AnnotatedChallenge],
                              config: configuration.NamespaceConfig) -> str:
        """Construct message for debug challenges prompt

        :param list achalls: A list of
            :class:`certbot.achallenges.AnnotatedChallenge`.
        :param certbot.configuration.NamespaceConfig config: current Certbot configuration
        :returns: Message containing challenge debug info
        :rtype: str

        """
        if config.verbose_count > 0:
            msg = []
            http01_achalls = {}
            dns01_achalls = {}
            for achall in achalls:
                if isinstance(achall.chall, challenges.HTTP01):
                    http01_achalls[achall.chall.uri(achall.domain)] = (
                        achall.validation(achall.account_key) + "\n"
                    )
                if isinstance(achall.chall, challenges.DNS01):
                    dns01_achalls[achall.validation_domain_name(achall.domain)] = (
                        achall.validation(achall.account_key) + "\n"
                    )
            if http01_achalls:
                msg.append("The following URLs should be accessible from the "
                           "internet and return the value mentioned:\n")
                for uri, key_authz in http01_achalls.items():
                    msg.append(f"URL: {uri}\nExpected value: {key_authz}")
            if dns01_achalls:
                msg.append("The following FQDNs should return a TXT resource "
                           "record with the value mentioned:\n")
                for fqdn, key_authz_hash in dns01_achalls.items():
                    msg.append(f"FQDN: {fqdn}\nExpected value: {key_authz_hash}")
            return "\n" + "\n".join(msg)
        else:
            return 'Pass "-v" for more info about challenges.'


def challb_to_achall(challb: messages.ChallengeBody, account_key: josepy.JWK,
                     domain: str) -> achallenges.AnnotatedChallenge:
    """Converts a ChallengeBody object to an AnnotatedChallenge.

    :param .ChallengeBody challb: ChallengeBody
    :param .JWK account_key: Authorized Account Key
    :param str domain: Domain of the challb

    :returns: Appropriate AnnotatedChallenge
    :rtype: :class:`certbot.achallenges.AnnotatedChallenge`

    """
    chall = challb.chall
    logger.info("%s challenge for %s", chall.typ, domain)

    if isinstance(chall, challenges.KeyAuthorizationChallenge):
        return achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=challb, domain=domain, account_key=account_key)
    elif isinstance(chall, challenges.DNS):
        return achallenges.DNS(challb=challb, domain=domain)
    raise errors.Error(f"Received unsupported challenge of type: {chall.typ}")


def gen_challenge_path(challbs: List[messages.ChallengeBody],
                       preferences: List[Type[challenges.Challenge]],
                       combinations: Tuple[Tuple[int, ...], ...]) -> Tuple[int, ...]:
    """Generate a plan to get authority over the identity.

    .. todo:: This can be possibly be rewritten to use resolved_combinations.

    :param tuple challbs: A tuple of challenges
        (:class:`acme.messages.Challenge`) from
        :class:`acme.messages.AuthorizationResource` to be
        fulfilled by the client in order to prove possession of the
        identifier.

    :param list preferences: List of challenge preferences for domain
        (:class:`acme.challenges.Challenge` subclasses)

    :param tuple combinations: A collection of sets of challenges from
        :class:`acme.messages.Challenge`, each of which would
        be sufficient to prove possession of the identifier.

    :returns: list of indices from ``challenges``.
    :rtype: list

    :raises certbot.errors.AuthorizationError: If a
        path cannot be created that satisfies the CA given the preferences and
        combinations.

    """
    if combinations:
        return _find_smart_path(challbs, preferences, combinations)
    return _find_dumb_path(challbs, preferences)


def _find_smart_path(challbs: List[messages.ChallengeBody],
                     preferences: List[Type[challenges.Challenge]],
                     combinations: Tuple[Tuple[int, ...], ...]
                     ) -> Tuple[int, ...]:
    """Find challenge path with server hints.

    Can be called if combinations is included. Function uses a simple
    ranking system to choose the combo with the lowest cost.

    """
    chall_cost = {}
    max_cost = 1
    for i, chall_cls in enumerate(preferences):
        chall_cost[chall_cls] = i
        max_cost += i

    # max_cost is now equal to sum(indices) + 1

    best_combo: Optional[Tuple[int, ...]] = None
    # Set above completing all of the available challenges
    best_combo_cost = max_cost

    combo_total = 0
    for combo in combinations:
        for challenge_index in combo:
            combo_total += chall_cost.get(challbs[
                challenge_index].chall.__class__, max_cost)

        if combo_total < best_combo_cost:
            best_combo = combo
            best_combo_cost = combo_total

        combo_total = 0

    if not best_combo:
        raise _report_no_chall_path(challbs)

    return best_combo


def _find_dumb_path(challbs: List[messages.ChallengeBody],
                    preferences: List[Type[challenges.Challenge]]) -> Tuple[int, ...]:
    """Find challenge path without server hints.

    Should be called if the combinations hint is not included by the
    server. This function either returns a path containing all
    challenges provided by the CA or raises an exception.

    """
    path = []
    for i, challb in enumerate(challbs):
        # supported is set to True if the challenge type is supported
        supported = next((True for pref_c in preferences
                          if isinstance(challb.chall, pref_c)), False)
        if supported:
            path.append(i)
        else:
            raise _report_no_chall_path(challbs)

    return tuple(path)


def _report_no_chall_path(challbs: List[messages.ChallengeBody]) -> errors.AuthorizationError:
    """Logs and return a raisable error reporting that no satisfiable chall path exists.

    :param challbs: challenges from the authorization that can't be satisfied

    :returns: An authorization error
    :rtype: certbot.errors.AuthorizationError

    """
    msg = ("Client with the currently selected authenticator does not support "
           "any combination of challenges that will satisfy the CA.")
    if len(challbs) == 1 and isinstance(challbs[0].chall, challenges.DNS01):
        msg += (
            " You may need to use an authenticator "
            "plugin that can do challenges over DNS.")
    logger.critical(msg)
    return errors.AuthorizationError(msg)


def _generate_failed_chall_msg(failed_achalls: List[achallenges.AnnotatedChallenge]) -> str:
    """Creates a user friendly error message about failed challenges.

    :param list failed_achalls: A list of failed
        :class:`certbot.achallenges.AnnotatedChallenge` with the same error
        type.
    :returns: A formatted error message for the client.
    :rtype: str

    """
    error = failed_achalls[0].error
    typ = error.typ
    if messages.is_acme_error(error):
        typ = error.code
    msg = []

    for achall in failed_achalls:
        msg.append("\n  Domain: %s\n  Type:   %s\n  Detail: %s\n" % (
            achall.domain, typ, achall.error.detail))

    return "".join(msg)
