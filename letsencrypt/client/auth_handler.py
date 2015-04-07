"""ACME AuthHandler."""
import logging
import sys

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
    :ivar dict authzr: ACME Challenge messages with domain as a key.
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

    def get_authorizations(self, domains):
        """Retrieve all authorizations for challenges.

        :param set domains: Domains for authorization

        :returns: tuple of lists of authorization resources. Takes the form of
            (`completed`, `failed`)
        rtype: tuple

        :raises LetsEncryptAuthHandlerError: If unable to retrieve all
            authorizations

        """
        progress = True
        while self.msgs and progress:
            progress = False
            self._satisfy_challenges()

            delete_list = []

            for dom in self.domains:
                if self._path_satisfied(dom):
                    self.acme_authorization(dom)
                    delete_list.append(dom)

            # This avoids modifying while iterating over the list
            if delete_list:
                self._cleanup_state(delete_list)
                progress = True

        if not progress:
            raise errors.LetsEncryptAuthHandlerError(
                "Unable to solve challenges for requested names.")

    def acme_authorization(self, domain):
        """Handle ACME "authorization" phase.

        :param str domain: domain that is requesting authorization

        :returns: ACME "authorization" message.
        :rtype: :class:`letsencrypt.acme.messages.Authorization`

        """
        try:
            auth = self.network.send_and_receive_expected(
                messages.AuthorizationRequest.create(
                    session_id=self.msgs[domain].session_id,
                    nonce=self.msgs[domain].nonce,
                    responses=self.responses[domain],
                    name=domain,
                    key=jose.HashableRSAKey(Crypto.PublicKey.RSA.importKey(
                        self.authkey[domain].pem))),
                messages.Authorization)
            logging.info("Received Authorization for %s", domain)
            return auth
        except errors.LetsEncryptClientError as err:
            logging.fatal(str(err))
            logging.fatal(
                "Failed Authorization procedure - cleaning up challenges")
            sys.exit(1)
        finally:
            self._cleanup_challenges(domain)

    def _satisfy_challenges(self):
        """Attempt to satisfy all saved challenge messages.

        .. todo:: It might be worth it to try different challenges to
            find one that doesn't throw an exception
        .. todo:: separate into more functions

        """
        logging.info("Performing the following challenges:")
        for dom in self.domains:
            path = gen_challenge_path(
                self.authzr[dom].challenges,
                self._get_chall_pref(dom),
                self.authzr[dom].combinations)

            dom_dv_c, dom_cont_c = self._challenge_factory(
                dom, path)
            self.dv_c.extend(dom_dv_c)
            self.cont_c.extend(dom_cont_c)

        cont_resp = []
        dv_resp = []
        try:
            if self.cont_c:
                cont_resp = self.cont_auth.perform(self.cont_c)
            if self.dv_c:
                dv_resp = self.dv_auth.perform(self.dv_c)
        # This will catch both specific types of errors.
        except errors.LetsEncryptAuthHandlerError as err:
            logging.critical("Failure in setting up challenges:")
            logging.critical(str(err))
            logging.info("Attempting to clean up outstanding challenges...")
            for dom in self.domains:
                self._cleanup_challenges(dom)

            raise errors.LetsEncryptAuthHandlerError(
                "Unable to perform challenges")

        assert len(cont_resp) == len(self.cont_c)
        assert len(dv_resp) == len(self.dv_c)

        logging.info("Ready for verification...")

        # Send all Responses
        self._respond(cont_resp, dv_resp)

    def _respond(self, cont_resp, dv_resp):
        """Send/Recieve confirmation of all challenges.

        .. note:: This method also cleans up the auth_handler state.

        """
        completed = []
        for chall, resp in itertools.izip(self.cont_c, cont_resp):
            if cont_resp[i]:
                self.network.answer_challenge(self.cont_c[i], cont_resp[i])
        for i in range(len(dv_resp)):
            if dv_resp[i]:
                self.network.answer_challenge(self.dv_c[i], cont_resp[i])



    def _get_chall_pref(self, domain):
        """Return list of challenge preferences.

        :param str domain: domain for which you are requesting preferences

        """
        chall_prefs = []
        chall_prefs.extend(self.cont_auth.get_chall_pref(domain))
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
            chall = self.msgs[domain].challenges[index]

            if isinstance(chall, challenges.DVSNI):
                logging.info("  DVSNI challenge for %s.", domain)
                achall = achallenges.DVSNI(
                    chall=chall, domain=domain, key=self.authkey[domain])
            elif isinstance(chall, challenges.SimpleHTTPS):
                logging.info("  SimpleHTTPS challenge for %s.", domain)
                achall = achallenges.SimpleHTTPS(
                    chall=chall, domain=domain, key=self.authkey[domain])
            elif isinstance(chall, challenges.DNS):
                logging.info("  DNS challenge for %s.", domain)
                achall = achallenges.DNS(chall=chall, domain=domain)

            elif isinstance(chall, challenges.RecoveryToken):
                logging.info("  Recovery Token Challenge for %s.", domain)
                achall = achallenges.RecoveryToken(chall=chall, domain=domain)
            elif isinstance(chall, challenges.RecoveryContact):
                logging.info("  Recovery Contact Challenge for %s.", domain)
                achall = achallenges.RecoveryContact(chall=chall, domain=domain)
            elif isinstance(chall, challenges.ProofOfPossession):
                logging.info("  Proof-of-Possession Challenge for %s", domain)
                achall = achallenges.ProofOfPossession(
                    chall=chall, domain=domain)

            else:
                raise errors.LetsEncryptClientError(
                    "Received unsupported challenge of type: %s", chall.typ)

            ichall = achallenges.Indexed(achall=achall, index=index)

            if isinstance(chall, challenges.ContinuityChallenge):
                cont_chall.append(ichall)
            elif isinstance(chall, challenges.DVChallenge):
                dv_chall.append(ichall)

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

    :raises letsencrypt.client.errors.LetsEncryptAuthHandlerError: If a
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
        raise errors.LetsEncryptAuthHandlerError(msg)

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
