"""ACME AuthHandler."""
import logging
import time

import six
import zope.component

from acme import challenges
from acme import messages

from certbot import achallenges
from certbot import errors
from certbot import error_handler
from certbot import interfaces


logger = logging.getLogger(__name__)


class AuthHandler(object):
    """ACME Authorization Handler for a client.

    :ivar auth: Authenticator capable of solving
        :class:`~acme.challenges.Challenge` types
    :type auth: :class:`certbot.interfaces.IAuthenticator`

    :ivar acme.client.Client acme: ACME client API.

    :ivar account: Client's Account
    :type account: :class:`certbot.account.Account`

    :ivar dict authzr: ACME Authorization Resource dict where keys are domains
        and values are :class:`acme.messages.AuthorizationResource`
    :ivar list achalls: DV challenges in the form of
        :class:`certbot.achallenges.AnnotatedChallenge`
    :ivar list pref_challs: sorted user specified preferred challenges
        type strings with the most preferred challenge listed first

    """
    def __init__(self, auth, acme, account, pref_challs):
        self.auth = auth
        self.acme = acme

        self.account = account
        self.authzr = dict()
        self.pref_challs = pref_challs

        # List must be used to keep responses straight.
        self.achalls = []

    def get_authorizations(self, domains, best_effort=False):
        """Retrieve all authorizations for challenges.

        :param list domains: Domains for authorization
        :param bool best_effort: Whether or not all authorizations are
             required (this is useful in renewal)

        :returns: List of authorization resources
        :rtype: list

        :raises .AuthorizationError: If unable to retrieve all
            authorizations

        """
        for domain in domains:
            self.authzr[domain] = self.acme.request_domain_challenges(
                domain, self.account.regr.new_authzr_uri)

        self._choose_challenges(domains)

        # While there are still challenges remaining...
        while self.achalls:
            resp = self._solve_challenges()
            logger.info("Waiting for verification...")

            # Send all Responses - this modifies achalls
            self._respond(resp, best_effort)

        # Just make sure all decisions are complete.
        self.verify_authzr_complete()

        # Only return valid authorizations
        retVal = [authzr for authzr in self.authzr.values()
                  if authzr.body.status == messages.STATUS_VALID]

        if not retVal:
            raise errors.AuthorizationError(
                "Challenges failed for all domains")

        return retVal

    def _choose_challenges(self, domains):
        """Retrieve necessary challenges to satisfy server."""
        logger.info("Performing the following challenges:")
        for dom in domains:
            path = gen_challenge_path(
                self.authzr[dom].body.challenges,
                self._get_chall_pref(dom),
                self.authzr[dom].body.combinations)

            dom_achalls = self._challenge_factory(
                dom, path)
            self.achalls.extend(dom_achalls)

    def _solve_challenges(self):
        """Get Responses for challenges from authenticators."""
        resp = []
        with error_handler.ErrorHandler(self._cleanup_challenges):
            try:
                if self.achalls:
                    resp = self.auth.perform(self.achalls)
            except errors.AuthorizationError:
                logger.critical("Failure in setting up challenges.")
                logger.info("Attempting to clean up outstanding challenges...")
                raise

        assert len(resp) == len(self.achalls)

        return resp

    def _respond(self, resp, best_effort):
        """Send/Receive confirmation of all challenges.

        .. note:: This method also cleans up the auth_handler state.

        """
        # TODO: chall_update is a dirty hack to get around acme-spec #105
        chall_update = dict()
        active_achalls = self._send_responses(self.achalls,
                                              resp, chall_update)

        # Check for updated status...
        try:
            self._poll_challenges(chall_update, best_effort)
        finally:
            # This removes challenges from self.achalls
            self._cleanup_challenges(active_achalls)

    def _send_responses(self, achalls, resps, chall_update):
        """Send responses and make sure errors are handled.

        :param dict chall_update: parameter that is updated to hold
            authzr -> list of outstanding solved annotated challenges

        """
        active_achalls = []
        for achall, resp in six.moves.zip(achalls, resps):
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
                    if best_effort:
                        comp_domains.add(domain)
                        logger.warning(
                            "Challenge failed for domain %s",
                            domain)
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
        chall_prefs = []
        # Make sure to make a copy...
        plugin_pref = self.auth.get_chall_pref(domain)
        if self.pref_challs:
            plugin_pref_types = set(chall.typ for chall in plugin_pref)
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

    def _cleanup_challenges(self, achall_list=None):
        """Cleanup challenges.

        If achall_list is not provided, cleanup all achallenges.

        """
        logger.info("Cleaning up challenges")

        if achall_list is None:
            achalls = self.achalls
        else:
            achalls = achall_list

        if achalls:
            self.auth.cleanup(achalls)
            for achall in achalls:
                self.achalls.remove(achall)

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

        :returns: achalls, list of challenge type
            :class:`certbot.achallenges.Indexed`
        :rtype: list

        :raises .errors.Error: if challenge type is not recognized

        """
        achalls = []

        for index in path:
            challb = self.authzr[domain].body.challenges[index]
            achalls.append(challb_to_achall(challb, self.account.key, domain))

        return achalls


def challb_to_achall(challb, account_key, domain):
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

    :raises certbot.errors.AuthorizationError: If a
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
        _report_no_chall_path()

    return best_combo


def _find_dumb_path(challbs, preferences):
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
            _report_no_chall_path()

    return path


def _report_no_chall_path():
    """Logs and raises an error that no satisfiable chall path exists."""
    msg = ("Client with the currently selected authenticator does not support "
           "any combination of challenges that will satisfy the CA.")
    logger.fatal(msg)
    raise errors.AuthorizationError(msg)


_ERROR_HELP_COMMON = (
    "To fix these errors, please make sure that your domain name was entered "
    "correctly and the DNS A record(s) for that domain contain(s) the "
    "right IP address.")


_ERROR_HELP = {
    "connection":
        _ERROR_HELP_COMMON + " Additionally, please check that your computer "
        "has a publicly routable IP address and that no firewalls are preventing "
        "the server from communicating with the client. If you're using the "
        "webroot plugin, you should also verify that you are serving files "
        "from the webroot path you provided.",
    "dnssec":
        _ERROR_HELP_COMMON + " Additionally, if you have DNSSEC enabled for "
        "your domain, please ensure that the signature is valid.",
    "malformed":
        "To fix these errors, please make sure that you did not provide any "
        "invalid information to the client, and try running Certbot "
        "again.",
    "serverInternal":
        "Unfortunately, an error on the ACME server prevented you from completing "
        "authorization. Please try again later.",
    "tls":
        _ERROR_HELP_COMMON + " Additionally, please check that you have an "
        "up-to-date TLS configuration that allows the server to communicate "
        "with the Certbot client.",
    "unauthorized": _ERROR_HELP_COMMON,
    "unknownHost": _ERROR_HELP_COMMON,
}


def _report_failed_challs(failed_achalls):
    """Notifies the user about failed challenges.

    :param set failed_achalls: A set of failed
        :class:`certbot.achallenges.AnnotatedChallenge`.

    """
    problems = dict()
    for achall in failed_achalls:
        if achall.error:
            problems.setdefault(achall.error.typ, []).append(achall)

    reporter = zope.component.getUtility(interfaces.IReporter)
    for achalls in six.itervalues(problems):
        reporter.add_message(
            _generate_failed_chall_msg(achalls), reporter.MEDIUM_PRIORITY)


def _generate_failed_chall_msg(failed_achalls):
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
    msg = ["The following errors were reported by the server:"]

    for achall in failed_achalls:
        msg.append("\n\nDomain: %s\nType:   %s\nDetail: %s" % (
            achall.domain, typ, achall.error.detail))

    if typ in _ERROR_HELP:
        msg.append("\n\n")
        msg.append(_ERROR_HELP[typ])

    return "".join(msg)
