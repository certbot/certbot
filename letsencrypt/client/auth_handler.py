"""ACME AuthHandler."""
import logging
import sys

from letsencrypt.client import acme
from letsencrypt.client import CONFIG
from letsencrypt.client import challenge_util
from letsencrypt.client import errors


class AuthHandler(object):  # pylint: disable=too-many-instance-attributes
    """ACME Authorization Handler for a client.

    :ivar dv_auth: Authenticator capable of solving CONFIG.DV_CHALLENGES
    :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar client_auth: Authenticator capable of solving CONFIG.CLIENT_CHALLENGES
    :type client_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar network: Network object for sending and receiving authorization
        messages
    :type network: :class:`letsencrypt.client.network.Network`

    :ivar list domains: list of str domains to get authorization
    :ivar dict authkey: Authorized Keys for each domain.
        values are of type :class:`letsencrypt.client.le_util.Key`
    :ivar dict responses: keys: domain, values: list of dict responses
    :ivar dict msgs: ACME Challenge messages with domain as a key
    :ivar dict paths: optimal path for authorization. eg. paths[domain]
    :ivar dict dv_c: Keys - domain, Values are DV challenges in the form of
        :class:`letsencrypt.client.challenge_util.IndexedChall`
    :ivar dict client_c: Keys - domain, Values are Client challenges in the form
        of :class:`letsencrypt.client.challenge_util.IndexedChall`

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
        :param dict msg: ACME challenge message

        :param authkey: authorized key for the challenge
        :type authkey: :class:`letsencrypt.client.le_util.Key`

        """
        if domain in self.domains:
            raise errors.LetsEncryptAuthHandlerError(
                "Multiple ACMEChallengeMessages for the same domain "
                "is not supported.")
        self.domains.append(domain)
        self.responses[domain] = ["null"] * len(msg["challenges"])
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
        :rtype: dict

        """
        try:
            auth = self.network.send_and_receive_expected(
                acme.authorization_request(
                    self.msgs[domain]["sessionID"],
                    domain,
                    self.msgs[domain]["nonce"],
                    self.responses[domain],
                    self.authkey[domain].pem),
                "authorization")
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

        """
        logging.info("Performing the following challenges:")
        for dom in self.domains:
            self.paths[dom] = gen_challenge_path(
                self.msgs[dom]["challenges"],
                self._get_chall_pref(dom),
                self.msgs[dom].get("combinations", None))

            self.dv_c[dom], self.client_c[dom] = self._challenge_factory(
                dom, self.paths[dom])

        # Flatten challs for authenticator functions and remove index
        # Order is important here as we will not expose the outside
        # Authenticator to our own indices.
        flat_client = []
        flat_auth = []
        for dom in self.domains:
            flat_client.extend(ichall.chall for ichall in self.client_c[dom])
            flat_auth.extend(ichall.chall for ichall in self.dv_c[dom])

        try:
            client_resp = self.client_auth.perform(flat_client)
            dv_resp = self.dv_auth.perform(flat_auth)
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
        self._assign_responses(client_resp, self.client_c)
        self._assign_responses(dv_resp, self.dv_c)

    def _assign_responses(self, flat_list, ichall_dict):
        """Assign responses from flat_list back to the IndexedChall dicts.

        :param list flat_list: flat_list of responses from an IAuthenticator
        :param dict ichall_dict: Master dict mapping all domains to a list of
            their associated 'client' and 'dv' IndexedChallenges, or their
            :class:`letsencrypt.client.challenge_util.IndexedChall` list

        """
        flat_index = 0
        for dom in self.domains:
            for ichall in ichall_dict[dom]:
                self.responses[dom][ichall.index] = flat_list[flat_index]
                flat_index += 1

    def _path_satisfied(self, dom):
        """Returns whether a path has been completely satisfied."""
        return all(
            None != self.responses[dom][i] and "null" != self.responses[dom][i]
            for i in self.paths[dom])

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
        self.dv_auth.cleanup([ichall.chall for ichall in self.dv_c[domain]])
        self.client_auth.cleanup(
            [ichall.chall for ichall in self.client_c[domain]])

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
            :class:`letsencrypt.client.challenge_util.IndexedChall`
            client_chall, list of
            :class:`letsencrypt.client.challenge_util.IndexedChall`
        :rtype: tuple

        :raises errors.LetsEncryptClientError: If Challenge type is not
            recognized

        """
        challenges = self.msgs[domain]["challenges"]

        dv_chall = []
        client_chall = []

        for index in path:
            chall = challenges[index]

            # Authenticator Challenges
            if chall["type"] in CONFIG.DV_CHALLENGES:
                dv_chall.append(challenge_util.IndexedChall(
                    self._construct_dv_chall(chall, domain), index))

            # Client Challenges
            elif chall["type"] in CONFIG.CLIENT_CHALLENGES:
                client_chall.append(challenge_util.IndexedChall(
                    self._construct_client_chall(chall, domain), index))

            else:
                raise errors.LetsEncryptClientError(
                    "Received unrecognized challenge of type: "
                    "%s" % chall["type"])

        return dv_chall, client_chall

    def _construct_dv_chall(self, chall, domain):
        """Construct Auth Type Challenges.

        :param dict chall: Single challenge
        :param str domain: challenge's domain

        :returns: challenge_util named tuple Chall object
        :rtype: `collections.namedtuple`

        :raises errors.LetsEncryptClientError: If unimplemented challenge exists

        """
        if chall["type"] == "dvsni":
            logging.info("  DVSNI challenge for name %s.", domain)
            return challenge_util.DvsniChall(
                domain, str(chall["r"]), str(chall["nonce"]),
                self.authkey[domain])

        elif chall["type"] == "simpleHttps":
            logging.info("  SimpleHTTPS challenge for name %s.", domain)
            return challenge_util.SimpleHttpsChall(
                domain, str(chall["token"]), self.authkey[domain])

        elif chall["type"] == "dns":
            logging.info("  DNS challenge for name %s.", domain)
            return challenge_util.DnsChall(domain, str(chall["token"]))

        else:
            raise errors.LetsEncryptClientError(
                "Unimplemented Auth Challenge: %s" % chall["type"])

    def _construct_client_chall(self, chall, domain):  # pylint: disable=no-self-use
        """Construct Client Type Challenges.

        :param dict chall: Single challenge
        :param str domain: challenge's domain

        :returns: challenge_util named tuple Chall object
        :rtype: `collections.namedtuple`

        :raises errors.LetsEncryptClientError: If unimplemented challenge exists

        """
        if chall["type"] == "recoveryToken":
            logging.info("  Recovery Token Challenge for name: %s.", domain)
            return challenge_util.RecTokenChall(domain)

        elif chall["type"] == "recoveryContact":
            logging.info("  Recovery Contact Challenge for name: %s.", domain)
            return challenge_util.RecContactChall(
                domain,
                chall.get("activationURL", None),
                chall.get("successURL", None),
                chall.get("contact", None))

        elif chall["type"] == "proofOfPossession":
            logging.info("  Proof-of-Possession Challenge for name: "
                         "%s", domain)
            return challenge_util.PopChall(
                domain, chall["alg"], chall["nonce"], chall["hints"])

        else:
            raise errors.LetsEncryptClientError(
                "Unimplemented Client Challenge: %s" % chall["type"])


def gen_challenge_path(challenges, preferences, combos=None):
    """Generate a plan to get authority over the identity.

    .. todo:: Make sure that the challenges are feasible...
        Example: Do you have the recovery key?

    :param list challenges: A list of challenges from ACME "challenge"
        server message to be fulfilled by the client in order to prove
        possession of the identifier.

    :param list preferences: List of challenge preferences for domain

    :param combos:  A collection of sets of challenges from ACME
        "challenge" server message ("combinations"), each of which would
        be sufficient to prove possession of the identifier.
    :type combos: list or None

    :returns: List of indices from `challenges`.
    :rtype: list

    """
    if combos:
        return _find_smart_path(challenges, preferences, combos)
    else:
        return _find_dumb_path(challenges, preferences)


def _find_smart_path(challenges, preferences, combos):
    """Find challenge path with server hints.

    Can be called if combinations is included. Function uses a simple
    ranking system to choose the combo with the lowest cost.

    :param list challenges: A list of challenges from ACME "challenge"
        server message to be fulfilled by the client in order to prove
        possession of the identifier.

    :param combos:  A collection of sets of challenges from ACME
        "challenge" server message ("combinations"), each of which would
        be sufficient to prove possession of the identifier.
    :type combos: list or None

    :returns: List of indices from `challenges`.
    :rtype: list

    """
    chall_cost = {}
    max_cost = 0
    for i, chall in enumerate(preferences):
        chall_cost[chall] = i
        max_cost += i

    best_combo = []
    # Set above completing all of the available challenges
    best_combo_cost = max_cost + 1

    combo_total = 0
    for combo in combos:
        for challenge_index in combo:
            combo_total += chall_cost.get(challenges[
                challenge_index]["type"], max_cost)
        if combo_total < best_combo_cost:
            best_combo = combo
            best_combo_cost = combo_total
            combo_total = 0

    if not best_combo:
        logging.fatal("Client does not support any combination of "
                      "challenges to satisfy ACME server")
        sys.exit(22)

    return best_combo


def _find_dumb_path(challenges, preferences):
    """Find challenge path without server hints.

    Should be called if the combinations hint is not included by the
    server. This function returns the best path that does not contain
    multiple mutually exclusive challenges.

    :param list challenges: A list of challenges from ACME "challenge"
        server message to be fulfilled by the client in order to prove
        possession of the identifier.

    :param list preferences: A list of preferences representing the
        challenge type found within the ACME spec. Each challenge type
        can only be listed once.

    :returns: List of indices from `challenges`.
    :rtype: list

    """
    # Add logic for a crappy server
    # Choose a DV
    path = []
    assert len(preferences) == len(set(preferences))
    for pref_c in preferences:
        for i, offered_challenge in enumerate(challenges):
            if (pref_c == offered_challenge["type"] and
                    is_preferred(offered_challenge["type"], path)):
                path.append((i, offered_challenge["type"]))

    return [i for (i, _) in path]


def is_preferred(offered_challenge_type, path):
    """Return whether or not the challenge is preferred in path."""
    for _, challenge_type in path:
        for mutually_exclusive in CONFIG.EXCLUSIVE_CHALLENGES:
            # Second part is in case we eventually allow multiple names
            # to be challenges at the same time
            if (challenge_type in mutually_exclusive and
                    offered_challenge_type in mutually_exclusive and
                    challenge_type != offered_challenge_type):
                return False

    return True
