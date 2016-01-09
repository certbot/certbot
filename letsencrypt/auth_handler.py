"""ACME AuthHandler."""
import itertools
import logging
import time

import zope.component

from acme import challenges
from acme import messages

from letsencrypt import achallenges
from letsencrypt import constants
from letsencrypt import errors
from letsencrypt import error_handler
from letsencrypt import interfaces


logger = logging.getLogger(__name__)


class AuthHandler(object):
    """ACME Authorization Handler for a client.

    :ivar dv_auth: Authenticator capable of solving
        :class:`~acme.challenges.DVChallenge` types
    :type dv_auth: :class:`letsencrypt.interfaces.IAuthenticator`

    :ivar cont_auth: Authenticator capable of solving
        :class:`~acme.challenges.ContinuityChallenge` types
    :type cont_auth: :class:`letsencrypt.interfaces.IAuthenticator`

    :ivar acme.client.Client acme: ACME client API.

    :ivar account: Client's Account
    :type account: :class:`letsencrypt.account.Account`

    :ivar dict authzr: ACME Authorization Resource dict where keys are domains
        and values are :class:`acme.messages.AuthorizationResource`
    :ivar list dv_c: DV challenges in the form of
        :class:`letsencrypt.achallenges.AnnotatedChallenge`
    :ivar list cont_c: Continuity challenges in the
        form of :class:`letsencrypt.achallenges.AnnotatedChallenge`

    """
    def __init__(self, dv_auth, cont_auth, acme, account):
        self.dv_auth = dv_auth
        self.cont_auth = cont_auth
        self.acme = acme

        self.account = account
        self.authzr = dict()

        # List must be used to keep responses straight.
        self.dv_c = []
        self.cont_c = []

    def get_authorizations(self, domains, best_effort=False):
        """Retrieve all authorizations for challenges.

        :param set domains: Domains for authorization
        :param bool best_effort: Whether or not all authorizations are
             required (this is useful in renewal)

        :returns: tuple of lists of authorization resources. Takes the
            form of (`completed`, `failed`)
        :rtype: tuple

        :raises .AuthorizationError: If unable to retrieve all
            authorizations

        """
        for domain in domains:
            self.authzr[domain] = self.acme.request_domain_challenges(
                domain, self.account.regr.new_authzr_uri)

        self._choose_challenges(domains)

        # While there are still challenges remaining...
        while self.dv_c or self.cont_c:
            cont_resp, dv_resp = self._solve_challenges()
            logger.info("Waiting for verification...")

            # Send all Responses - this modifies dv_c and cont_c
            self._respond(cont_resp, dv_resp, best_effort)

        # Just make sure all decisions are complete.
        self.verify_authzr_complete()
        # Only return valid authorizations
        return [authzr for authzr in self.authzr.values()
                if authzr.body.status == messages.STATUS_VALID]

    def _choose_challenges(self, domains):
        """Retrieve necessary challenges to satisfy server."""
        logger.info("Performing the following challenges:")
        for dom in domains:
            path = gen_challenge_path(
                self.authzr[dom].body.challenges,
                self._get_chall_pref(dom),
                self.authzr[dom].body.combinations)

            dom_cont_c, dom_dv_c = self._challenge_factory(
                dom, path)
            self.dv_c.extend(dom_dv_c)
            self.cont_c.extend(dom_cont_c)

    def _solve_challenges(self):
        """Get Responses for challenges from authenticators."""
        cont_resp = []
        dv_resp = []
        with error_handler.ErrorHandler(self._cleanup_challenges):
            try:
                if self.cont_c:
                    cont_resp = self.cont_auth.perform(self.cont_c)
                if self.dv_c:
                    dv_resp = self.dv_auth.perform(self.dv_c)
            except errors.AuthorizationError:
                logger.critical("Failure in setting up challenges.")
                logger.info("Attempting to clean up outstanding challenges...")
                raise

        assert len(cont_resp) == len(self.cont_c)
        assert len(dv_resp) == len(self.dv_c)

        return cont_resp, dv_resp

    def _respond(self, cont_resp, dv_resp, best_effort):
        """Send/Receive confirmation of all challenges.

        .. note:: This method also cleans up the auth_handler state.

        """
        # TODO: chall_update is a dirty hack to get around acme-spec #105
        chall_update = dict()
        active_achalls = []
        active_achalls.extend(
            self._send_responses(self.dv_c, dv_resp, chall_update))
        active_achalls.extend(
            self._send_responses(self.cont_c, cont_resp, chall_update))

        # Check for updated status...
        try:
            self._poll_challenges(chall_update, best_effort)
        finally:
            # This removes challenges from self.dv_c and self.cont_c
            self._cleanup_challenges(active_achalls)

    def _send_responses(self, achalls, resps, chall_update):
        """Send responses and make sure errors are handled.

        :param dict chall_update: parameter that is updated to hold
            authzr -> list of outstanding solved annotated challenges

        """
        active_achalls = []
        for achall, resp in itertools.izip(achalls, resps):
            # This line needs to be outside of the if block below to
            # ensure failed challenges are cleaned up correctly
            active_achalls.append(achall)

            # Don't send challenges for None and False authenticator responses
            if resp is not None and resp:
                self.acme.answer_challenge(achall.challb, resp)
                # TODO: answer_challenge returns challr, with URI,
                # that can be used in _find_updated_challr
                # comparisons...
                if achall.domain in chall_update:
                    chall_update[achall.domain].append(achall)
                else:
                    chall_update[achall.domain] = [achall]

        return active_achalls

    def _poll_challenges(
            self, chall_update, best_effort, min_sleep=3, max_rounds=15):
        """Wait for all challenge results to be determined."""
        dom_to_check = set(chall_update.keys())
        comp_domains = set()
        rounds = 0

        while dom_to_check and rounds < max_rounds:
            # TODO: Use retry-after...
            time.sleep(min_sleep)
            all_failed_achalls = set()
            for domain in dom_to_check:
                comp_achalls, failed_achalls = self._handle_check(
                    domain, chall_update[domain])

                if len(comp_achalls) == len(chall_update[domain]):
                    comp_domains.add(domain)
                elif not failed_achalls:
                    for achall, _ in comp_achalls:
                        chall_update[domain].remove(achall)
                # We failed some challenges... damage control
                else:
                    # Right now... just assume a loss and carry on...
                    if best_effort:
                        comp_domains.add(domain)
                    else:
                        all_failed_achalls.update(
                            updated for _, updated in failed_achalls)

            if all_failed_achalls:
                _report_failed_challs(all_failed_achalls)
                raise errors.FailedChallenges(all_failed_achalls)

            dom_to_check -= comp_domains
            comp_domains.clear()
            rounds += 1

    def _handle_check(self, domain, achalls):
        """Returns tuple of ('completed', 'failed')."""
        completed = []
        failed = []

        self.authzr[domain], _ = self.acme.poll(self.authzr[domain])
        if self.authzr[domain].body.status == messages.STATUS_VALID:
            return achalls, []

        # Note: if the whole authorization is invalid, the individual failed
        #     challenges will be determined here...
        for achall in achalls:
            updated_achall = achall.update(challb=self._find_updated_challb(
                self.authzr[domain], achall))

            # This does nothing for challenges that have yet to be decided yet.
            if updated_achall.status == messages.STATUS_VALID:
                completed.append((achall, updated_achall))
            elif updated_achall.status == messages.STATUS_INVALID:
                failed.append((achall, updated_achall))

        return completed, failed

    def _find_updated_challb(self, authzr, achall):  # pylint: disable=no-self-use
        """Find updated challenge body within Authorization Resource.

        .. warning:: This assumes only one instance of type of challenge in
            each challenge resource.

        :param .AuthorizationResource authzr: Authorization Resource
        :param .AnnotatedChallenge achall: Annotated challenge for which
            to get status

        """
        for authzr_challb in authzr.body.challenges:
            if type(authzr_challb.chall) is type(achall.challb.chall):  # noqa
                return authzr_challb
        raise errors.AuthorizationError(
            "Target challenge not found in authorization resource")

    def _get_chall_pref(self, domain):
        """Return list of challenge preferences.

        :param str domain: domain for which you are requesting preferences

        """
        # Make sure to make a copy...
        chall_prefs = []
        chall_prefs.extend(self.cont_auth.get_chall_pref(domain))
        chall_prefs.extend(self.dv_auth.get_chall_pref(domain))
        return chall_prefs

    def _cleanup_challenges(self, achall_list=None):
        """Cleanup challenges.

        If achall_list is not provided, cleanup all achallenges.

        """
        logger.info("Cleaning up challenges")

        if achall_list is None:
            dv_c = self.dv_c
            cont_c = self.cont_c
        else:
            dv_c = [achall for achall in achall_list
                    if isinstance(achall.chall, challenges.DVChallenge)]
            cont_c = [achall for achall in achall_list if isinstance(
                achall.chall, challenges.ContinuityChallenge)]

        if dv_c:
            self.dv_auth.cleanup(dv_c)
            for achall in dv_c:
                self.dv_c.remove(achall)
        if cont_c:
            self.cont_auth.cleanup(cont_c)
            for achall in cont_c:
                self.cont_c.remove(achall)

    def verify_authzr_complete(self):
        """Verifies that all authorizations have been decided.

        :returns: Whether all authzr are complete
        :rtype: bool

        """
        for authzr in self.authzr.values():
            if (authzr.body.status != messages.STATUS_VALID and
                    authzr.body.status != messages.STATUS_INVALID):
                raise errors.AuthorizationError("Incomplete authorizations")

    def _challenge_factory(self, domain, path):
        """Construct Namedtuple Challenges

        :param str domain: domain of the enrollee

        :param list path: List of indices from `challenges`.

        :returns: dv_chall, list of DVChallenge type
            :class:`letsencrypt.achallenges.Indexed`
            cont_chall, list of ContinuityChallenge type
            :class:`letsencrypt.achallenges.Indexed`
        :rtype: tuple

        :raises .errors.Error: if challenge type is not recognized

        """
        dv_chall = []
        cont_chall = []

        for index in path:
            challb = self.authzr[domain].body.challenges[index]
            chall = challb.chall

            achall = challb_to_achall(challb, self.account.key, domain)

            if isinstance(chall, challenges.ContinuityChallenge):
                cont_chall.append(achall)
            elif isinstance(chall, challenges.DVChallenge):
                dv_chall.append(achall)

        return cont_chall, dv_chall


def challb_to_achall(challb, account_key, domain):
    """Converts a ChallengeBody object to an AnnotatedChallenge.

    :param .ChallengeBody challb: ChallengeBody
    :param .JWK account_key: Authorized Account Key
    :param str domain: Domain of the challb

    :returns: Appropriate AnnotatedChallenge
    :rtype: :class:`letsencrypt.achallenges.AnnotatedChallenge`

    """
    chall = challb.chall
    logger.info("%s challenge for %s", chall.typ, domain)

    if isinstance(chall, challenges.KeyAuthorizationChallenge):
        return achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=challb, domain=domain, account_key=account_key)
    elif isinstance(chall, challenges.DNS):
        return achallenges.DNS(challb=challb, domain=domain)
    elif isinstance(chall, challenges.RecoveryContact):
        return achallenges.RecoveryContact(
            challb=challb, domain=domain)
    elif isinstance(chall, challenges.ProofOfPossession):
        return achallenges.ProofOfPossession(
            challb=challb, domain=domain)
    else:
        raise errors.Error(
            "Received unsupported challenge of type: %s", chall.typ)


def gen_challenge_path(challbs, preferences, combinations):
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

    :returns: tuple of indices from ``challenges``.
    :rtype: tuple

    :raises letsencrypt.errors.AuthorizationError: If a
        path cannot be created that satisfies the CA given the preferences and
        combinations.

    """
    if combinations:
        return _find_smart_path(challbs, preferences, combinations)
    else:
        return _find_dumb_path(challbs, preferences)


def _find_smart_path(challbs, preferences, combinations):
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

    best_combo = []
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
        msg = ("Client does not support any combination of challenges that "
               "will satisfy the CA.")
        logger.fatal(msg)
        raise errors.AuthorizationError(msg)

    return best_combo


def _find_dumb_path(challbs, preferences):
    """Find challenge path without server hints.

    Should be called if the combinations hint is not included by the
    server. This function returns the best path that does not contain
    multiple mutually exclusive challenges.

    """
    assert len(preferences) == len(set(preferences))

    path = []
    satisfied = set()
    for pref_c in preferences:
        for i, offered_challb in enumerate(challbs):
            if (isinstance(offered_challb.chall, pref_c) and
                    is_preferred(offered_challb, satisfied)):
                path.append(i)
                satisfied.add(offered_challb)
    return path


def mutually_exclusive(obj1, obj2, groups, different=False):
    """Are two objects mutually exclusive?"""
    for group in groups:
        obj1_present = False
        obj2_present = False

        for obj_cls in group:
            obj1_present |= isinstance(obj1, obj_cls)
            obj2_present |= isinstance(obj2, obj_cls)

            if obj1_present and obj2_present and (
                    not different or not isinstance(obj1, obj2.__class__)):
                return False
    return True


def is_preferred(offered_challb, satisfied,
                 exclusive_groups=constants.EXCLUSIVE_CHALLENGES):
    """Return whether or not the challenge is preferred in path."""
    for challb in satisfied:
        if not mutually_exclusive(
                offered_challb.chall, challb.chall, exclusive_groups,
                different=True):
            return False
    return True


_ERROR_HELP_COMMON = (
    "To fix these errors, please make sure that your domain name was entered "
    "correctly and the DNS A record(s) for that domain contain(s) the "
    "right IP address.")


_ERROR_HELP = {
    "connection":
        _ERROR_HELP_COMMON + " Additionally, please check that your computer "
        "has a publicly routable IP address and that no firewalls are preventing "
        "the server from communicating with the client.",
    "dnssec":
        _ERROR_HELP_COMMON + " Additionally, if you have DNSSEC enabled for "
        "your domain, please ensure that the signature is valid.",
    "malformed":
        "To fix these errors, please make sure that you did not provide any "
        "invalid information to the client, and try running Let's Encrypt "
        "again.",
    "serverInternal":
        "Unfortunately, an error on the ACME server prevented you from completing "
        "authorization. Please try again later.",
    "tls":
        _ERROR_HELP_COMMON + " Additionally, please check that you have an "
        "up-to-date TLS configuration that allows the server to communicate "
        "with the Let's Encrypt client.",
    "unauthorized": _ERROR_HELP_COMMON,
    "unknownHost": _ERROR_HELP_COMMON,
}


def _report_failed_challs(failed_achalls):
    """Notifies the user about failed challenges.

    :param set failed_achalls: A set of failed
        :class:`letsencrypt.achallenges.AnnotatedChallenge`.

    """
    problems = dict()
    for achall in failed_achalls:
        if achall.error:
            problems.setdefault(achall.error.typ, []).append(achall)

    reporter = zope.component.getUtility(interfaces.IReporter)
    for achalls in problems.itervalues():
        reporter.add_message(
            _generate_failed_chall_msg(achalls), reporter.MEDIUM_PRIORITY)


def _generate_failed_chall_msg(failed_achalls):
    """Creates a user friendly error message about failed challenges.

    :param list failed_achalls: A list of failed
        :class:`letsencrypt.achallenges.AnnotatedChallenge` with the same error
        type.

    :returns: A formatted error message for the client.
    :rtype: str

    """
    typ = failed_achalls[0].error.typ
    msg = ["The following errors were reported by the server:"]

    for achall in failed_achalls:
        msg.append("\n\nDomain: %s\nType:   %s\nDetail: %s" % (
            achall.domain, achall.error.typ, achall.error.detail))

    if typ in _ERROR_HELP:
        msg.append("\n\n")
        msg.append(_ERROR_HELP[typ])

    return "".join(msg)
