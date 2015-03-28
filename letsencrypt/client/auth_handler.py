"""ACME AuthHandler."""
import logging
import sys

import Crypto.PublicKey.RSA

from letsencrypt.acme import challenges
from letsencrypt.acme import messages

from letsencrypt.client import achallenges
from letsencrypt.client import constants
from letsencrypt.client import errors


class AuthHandler(object):  # pylint: disable=too-many-instance-attributes
    """ACME Authorization Handler for a client.

    :ivar dv_auth: Authenticator capable of solving
        :const:`~letsencrypt.client.constants.DV_CHALLENGES`
    :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar client_auth: Authenticator capable of solving
        :const:`~letsencrypt.client_auth.constants.CLIENT_CHALLENGES`
    :type client_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar network: Network object for sending and receiving authorization
        messages
    :type network: :class:`letsencrypt.client.network.Network`

    :ivar list domains: list of str domains to get authorization
    :ivar dict authkey: Authorized Keys for each domain.
        values are of type :class:`letsencrypt.client.le_util.Key`
    :ivar dict responses: keys: domain, values: list of responses
        (:class:`letsencrypt.acme.challenges.ChallengeResponse`.
    :ivar dict msgs: ACME Challenge messages with domain as a key.
    :ivar dict paths: optimal path for authorization. eg. paths[domain]
    :ivar dict dv_c: Keys - domain, Values are DV challenges in the form of
        :class:`letsencrypt.client.achallenges.Indexed`
    :ivar dict client_c: Keys - domain, Values are Client challenges in the form
        of :class:`letsencrypt.client.achallenges.Indexed`

    """
    def __init__(self, dv_auth, client_auth, network):
        self.dv_auth = dv_auth
        self.client_auth = client_auth
        self.network = network

        self.domains = []
        self.authkey = dict()
        self.responses = dict()
        self.msgs = dict()
        self.paths = dict()

        self.dv_c = dict()
        self.client_c = dict()

    def add_chall_msg(self, domain, msg, authkey):
        """Add a challenge message to the AuthHandler.

        :param str domain: domain for authorization

        :param msg: ACME "challenge" message
        :type msg: :class:`letsencrypt.acme.message.Challenge`

        :param authkey: authorized key for the challenge
        :type authkey: :class:`letsencrypt.client.le_util.Key`

        """
        if domain in self.domains:
            raise errors.LetsEncryptAuthHandlerError(
                "Multiple ACMEChallengeMessages for the same domain "
                "is not supported.")
        self.domains.append(domain)
        self.responses[domain] = [None] * len(msg.challenges)
        self.msgs[domain] = msg
        self.authkey[domain] = authkey

    def get_authorizations(self):
        """Retreive all authorizations for challenges.

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
                    key=Crypto.PublicKey.RSA.importKey(
                        self.authkey[domain].pem)),
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
            self.paths[dom] = gen_challenge_path(
                self.msgs[dom].challenges,
                self._get_chall_pref(dom),
                self.msgs[dom].combinations)

            self.dv_c[dom], self.client_c[dom] = self._challenge_factory(
                dom, self.paths[dom])

        # Flatten challs for authenticator functions and remove index
        # Order is important here as we will not expose the outside
        # Authenticator to our own indices.
        flat_client = []
        flat_dv = []

        for dom in self.domains:
            flat_client.extend(ichall.achall for ichall in self.client_c[dom])
            flat_dv.extend(ichall.achall for ichall in self.dv_c[dom])

        client_resp = []
        dv_resp = []
        try:
            if flat_client:
                client_resp = self.client_auth.perform(flat_client)
            if flat_dv:
                dv_resp = self.dv_auth.perform(flat_dv)
        # This will catch both specific types of errors.
        except errors.LetsEncryptAuthHandlerError as err:
            logging.critical("Failure in setting up challenges:")
            logging.critical(str(err))
            logging.info("Attempting to clean up outstanding challenges...")
            for dom in self.domains:
                self._cleanup_challenges(dom)

            raise errors.LetsEncryptAuthHandlerError(
                "Unable to perform challenges")

        logging.info("Ready for verification...")

        # Assemble Responses
        if client_resp:
            self._assign_responses(client_resp, self.client_c)
        if dv_resp:
            self._assign_responses(dv_resp, self.dv_c)

    def _assign_responses(self, flat_list, ichall_dict):
        """Assign responses from flat_list back to the Indexed dicts.

        :param list flat_list: flat_list of responses from an IAuthenticator
        :param dict ichall_dict: Master dict mapping all domains to a list of
            their associated 'client' and 'dv' Indexed challenges, or their
            :class:`letsencrypt.client.achallenges.Indexed` list

        """
        flat_index = 0
        for dom in self.domains:
            for ichall in ichall_dict[dom]:
                self.responses[dom][ichall.index] = flat_list[flat_index]
                flat_index += 1

    def _path_satisfied(self, dom):
        """Returns whether a path has been completely satisfied."""
        # Make sure that there are no 'None' or 'False' entries along path.
        return all(self.responses[dom][i] for i in self.paths[dom])

    def _get_chall_pref(self, domain):
        """Return list of challenge preferences.

        :param str domain: domain for which you are requesting preferences

        """
        chall_prefs = []
        chall_prefs.extend(self.client_auth.get_chall_pref(domain))
        chall_prefs.extend(self.dv_auth.get_chall_pref(domain))
        return chall_prefs

    def _cleanup_challenges(self, domain):
        """Cleanup configuration challenges

        :param str domain: domain for which to clean up challenges

        """
        logging.info("Cleaning up challenges for %s", domain)
        # These are indexed challenges... give just the challenges to the auth
        # Chose to make these lists instead of a generator to make it easier to
        # work with...
        dv_list = [ichall.achall for ichall in self.dv_c[domain]]
        client_list = [ichall.achall for ichall in self.client_c[domain]]
        if dv_list:
            self.dv_auth.cleanup(dv_list)
        if client_list:
            self.client_auth.cleanup(client_list)

    def _cleanup_state(self, delete_list):
        """Cleanup state after an authorization is received.

        :param list delete_list: list of domains in str form

        """
        for domain in delete_list:
            del self.msgs[domain]
            del self.responses[domain]
            del self.paths[domain]

            del self.authkey[domain]

            del self.client_c[domain]
            del self.dv_c[domain]

            self.domains.remove(domain)

    def _challenge_factory(self, domain, path):
        """Construct Namedtuple Challenges

        :param str domain: domain of the enrollee

        :param list path: List of indices from `challenges`.

        :returns: dv_chall, list of
            :class:`letsencrypt.client.achallenges.Indexed`
            client_chall, list of
            :class:`letsencrypt.client.achallenges.Indexed`
        :rtype: tuple

        :raises errors.LetsEncryptClientError: If Challenge type is not
            recognized

        """
        dv_chall = []
        client_chall = []

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

            if isinstance(chall, challenges.ClientChallenge):
                client_chall.append(ichall)
            elif isinstance(chall, challenges.DVChallenge):
                dv_chall.append(ichall)

        return dv_chall, client_chall


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
    # This cannot be a set() because POP challenge is not currently hashable
    satisfied = []
    for pref_c in preferences:
        for i, offered_chall in enumerate(challs):
            if (isinstance(offered_chall, pref_c) and
                    is_preferred(offered_chall, satisfied)):
                path.append(i)
                satisfied.append(offered_chall)
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
