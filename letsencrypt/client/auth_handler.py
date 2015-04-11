"""ACME AuthHandler."""
import itertools
import logging
import sys
import time

import Crypto.PublicKey.RSA

from letsencrypt.acme import challenges
from letsencrypt.acme import jose
from letsencrypt.acme import messages2

from letsencrypt.client import achallenges
from letsencrypt.client import constants
from letsencrypt.client import errors


class AuthHandler(object):  # pylint: disable=too-many-instance-attributes
    """ACME Authorization Handler for a client.

    :ivar dv_auth: Authenticator capable of solving
        :class:`~letsencrypt.acme.challenges.DVChallenge` types
    :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar cont_auth: Authenticator capable of solving
        :class:`~letsencrypt.acme.challenges.ContinuityChallenge` types
    :type cont_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar network: Network object for sending and receiving authorization
        messages
    :type network: :class:`letsencrypt.client.network2.Network`

    :ivar list domains: list of str domains to get authorization
    :ivar dict authkey: Authorized Keys for each domain.
        values are of type :class:`letsencrypt.client.le_util.Key`
    :ivar dict authzr: ACME Authorization Resource dict where keys are domains.
    :ivar list dv_c: Keys - DV challenges in the form of
        :class:`letsencrypt.client.achallenges.Indexed`
    :ivar list cont_c: Keys - Continuity challenges in the
        form of :class:`letsencrypt.client.achallenges.Indexed`

    """
    def __init__(self, dv_auth, cont_auth, network, authkey):
        self.dv_auth = dv_auth
        self.cont_auth = cont_auth
        self.network = network

        self.domains = []
        self.authkey = authkey
        self.authzr = dict()

        self.dv_c = []
        self.cont_c = []

    def get_authorizations(self, domains, new_authz_uri):
        """Retrieve all authorizations for challenges.

        :param set domains: Domains for authorization

        :returns: tuple of lists of authorization resources. Takes the form of
            (`completed`, `failed`)
        rtype: tuple

        :raises AuthHandlerError: If unable to retrieve all
            authorizations

        """
        for domain in domains:
            self.authzr[domain] = self.network.request_domain_challenges(
                domain, new_authz_uri)
        self._choose_challenges(domains)
        cont_resp, dv_resp = self._get_responses()
        logging.info("Ready for verification...")

        # Send all Responses
        self._respond(cont_resp, dv_resp)

        return self._verify_auths()

    def _choose_challenges(self, domains):
        logging.info("Performing the following challenges:")
        for dom in domains:
            path = gen_challenge_path(
                self.authzr[dom].body.challenges,
                self._get_chall_pref(dom),
                self.authzr[dom].body.combinations)

            dom_dv_c, dom_cont_c = self._challenge_factory(
                dom, path)
            self.dv_c.extend(dom_dv_c)
            self.cont_c.extend(dom_cont_c)

    def _get_responses(self):
        """Get Responses for challenges from authenticators."""
        cont_resp = []
        dv_resp = []
        try:
            if self.cont_c:
                cont_resp = self.cont_auth.perform(self.cont_c)
            if self.dv_c:
                dv_resp = self.dv_auth.perform(self.dv_c)
        # This will catch both specific types of errors.
        except errors.AuthHandlerError as err:
            logging.critical("Failure in setting up challenges.")
            logging.info("Attempting to clean up outstanding challenges...")
            self._cleanup_challenges()
            raise errors.AuthHandlerError(
                "Unable to perform challenges")

        assert len(cont_resp) == len(self.cont_c)
        assert len(dv_resp) == len(self.dv_c)

        return cont_resp, dv_resp

    def _verify_auths(self):
        time.sleep(6)
        for domain in self.authzr:
            self.authzr[domain], resp = self.network.poll(self.authzr[domain])
            if self.authzr[domain].body.status == messages2.STATUS_INVALID:
                raise errors.AuthHandlerError(
                    "Unable to retrieve authorization for %s" % domain)

        self._cleanup_challenges()
        return [self.authzr[domain] for domain in self.authzr]

    def _respond(self, cont_resp, dv_resp):
        """Send/Receive confirmation of all challenges.

        .. note:: This method also cleans up the auth_handler state.

        """
        chall_update = dict()
        self._send_responses(self.dv_c, dv_resp, chall_update)
        self._send_responses(self.cont_c, cont_resp, chall_update)

        # self._poll_challenges(chall_update)

    def _send_responses(self, achalls, resps, chall_update):
        """Send responses and make sure errors are handled."""
        for achall, resp in itertools.izip(achalls, resps):
            if resp:
                challr = self.network.answer_challenge(achall.chall, resp)
                chall_update[achall.domain] = chall_update.get(
                    achall.domain, []).append(challr)

    # def _poll_challenges(self, chall_update):
    #     to_check = chall_update.keys()
    #     completed = []
    #     while to_check:
    #
    # def _handle_to_check(self):
    #     for domain in to_check:
    #         self.authzr[domain] = self.network.poll(self.authzr[domain])
    #         if self.authzr[domain].status == messages2.STATUS_VALID:
    #             completed.append(domain)
    #         if self.authzr[domain].status == messages2.STATUS_INVALID:
    #             logging.error("Failed authorization for %s", domain)
    #             raise errors.AuthHandlerError(
    #                 "Failed Authorization for %s" % domain)
    #         for challr in chall_update[domain]:
    #             status = self._get_status_of_chall(self.authzr[domain], challr)
    #             if status == messages2.STATUS_VALID:
    #                 chall_update[domain].remove(challr)
    #             elif status == messages2.STATUS_INVALID:
    #                 raise errors.AuthHandlerError(
    #                     "Failed %s challenge for domain %s" % (
    #                         challr.body.chall.typ, domain))
    #
    # def _get_status_of_chall(self, authzr, challr):
    #     for challb in authzr.challenges:
    #         # TODO: Use better identifiers... instead of type
    #         if isinstance(challb.chall, challr.body.chall):
    #             return challb.status

    def _get_chall_pref(self, domain):
        """Return list of challenge preferences.

        :param str domain: domain for which you are requesting preferences

        """
        chall_prefs = self.cont_auth.get_chall_pref(domain)
        chall_prefs.extend(self.dv_auth.get_chall_pref(domain))
        return chall_prefs

    def _cleanup_challenges(self):
        """Cleanup all configuration challenges."""
        logging.info("Cleaning up all challenges")

        if self.dv_c:
            self.dv_auth.cleanup(self.dv_c)
        if self.cont_c:
            self.cont_auth.cleanup(self.cont_c)

    def _challenge_factory(self, domain, path):
        """Construct Namedtuple Challenges

        :param str domain: domain of the enrollee

        :param list path: List of indices from `challenges`.

        :returns: dv_chall, list of DVChallenge type
            :class:`letsencrypt.client.achallenges.Indexed`
            cont_chall, list of ContinuityChallenge type
            :class:`letsencrypt.client.achallenges.Indexed`
        :rtype: tuple

        :raises errors.LetsEncryptClientError: If Challenge type is not
            recognized

        """
        dv_chall = []
        cont_chall = []

        for index in path:
            chall = self.authzr[domain].body.challenges[index]

            if isinstance(chall, challenges.DVSNI):
                logging.info("  DVSNI challenge for %s.", domain)
                achall = achallenges.DVSNI(
                    chall=chall, domain=domain, key=self.authkey)
            elif isinstance(chall, challenges.SimpleHTTPS):
                logging.info("  SimpleHTTPS challenge for %s.", domain)
                achall = achallenges.SimpleHTTPS(
                    chall=chall, domain=domain, key=self.authkey)
            elif isinstance(chall, challenges.DNS):
                logging.info("  DNS challenge for %s.", domain)
                achall = achallenges.DNS(chall=chall, domain=domain)

            elif isinstance(chall, challenges.RecoveryToken):
                logging.info("  Recovery Token Challenge for %s.", domain)
                achall = achallenges.RecoveryToken(chall=chall, domain=domain)
            elif isinstance(chall, challenges.RecoveryContact):
                logging.info("  Recovery Contact Challenge for %s.", domain)
                achall = achallenges.RecoveryContact(
                    chall=chall, domain=domain)
            elif isinstance(chall, challenges.ProofOfPossession):
                logging.info("  Proof-of-Possession Challenge for %s", domain)
                achall = achallenges.ProofOfPossession(
                    chall=chall, domain=domain)

            else:
                raise errors.LetsEncryptClientError(
                    "Received unsupported challenge of type: %s",
                    chall.typ)

            if isinstance(chall, challenges.ContinuityChallenge):
                cont_chall.append(achall)
            elif isinstance(chall, challenges.DVChallenge):
                dv_chall.append(achall)

        return dv_chall, cont_chall


def gen_challenge_path(challs, preferences, combinations):
    """Generate a plan to get authority over the identity.

    .. todo:: This can be possibly be rewritten to use resolved_combinations.

    :param tuple challs: A tuple of challenges
        (:class:`letsencrypt.acme.challenges.Challenge`) from
        :class:`letsencrypt.acme.messages.Challenge` server message to
        be fulfilled by the client in order to prove possession of the
        identifier.

    :param list preferences: List of challenge preferences for domain
        (:class:`letsencrypt.acme.challenges.Challenge` subclasses)

    :param tuple combinations: A collection of sets of challenges from
        :class:`letsencrypt.acme.messages.Challenge`, each of which would
        be sufficient to prove possession of the identifier.

    :returns: tuple of indices from ``challenges``.
    :rtype: tuple

    :raises letsencrypt.client.errors.AuthHandlerError: If a
        path cannot be created that satisfies the CA given the preferences and
        combinations.

    """
    if combinations:
        return _find_smart_path(challs, preferences, combinations)
    else:
        return _find_dumb_path(challs, preferences)


def _find_smart_path(challs, preferences, combinations):
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
            combo_total += chall_cost.get(challs[
                challenge_index].__class__, max_cost)

        if combo_total < best_combo_cost:
            best_combo = combo
            best_combo_cost = combo_total

        combo_total = 0

    if not best_combo:
        msg = ("Client does not support any combination of challenges that "
               "will satisfy the CA.")
        logging.fatal(msg)
        raise errors.AuthHandlerError(msg)

    return best_combo


def _find_dumb_path(challs, preferences):
    """Find challenge path without server hints.

    Should be called if the combinations hint is not included by the
    server. This function returns the best path that does not contain
    multiple mutually exclusive challenges.

    """
    assert len(preferences) == len(set(preferences))

    path = []
    satisfied = set()
    for pref_c in preferences:
        for i, offered_chall in enumerate(challs):
            if (isinstance(offered_chall, pref_c) and
                    is_preferred(offered_chall, satisfied)):
                path.append(i)
                satisfied.add(offered_chall)
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


def is_preferred(offered_chall, satisfied,
                 exclusive_groups=constants.EXCLUSIVE_CHALLENGES):
    """Return whether or not the challenge is preferred in path."""
    for chall in satisfied:
        if not mutually_exclusive(
                offered_chall, chall, exclusive_groups, different=True):
            return False
    return True
