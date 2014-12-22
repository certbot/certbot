"""ACME challenge."""
import logging
import sys

from letsencrypt.client import CONFIG


def gen_challenge_path(challenges, combos=None):
    """Generate a plan to get authority over the identity.

    .. todo:: Make sure that the challenges are feasible...
        Example: Do you have the recovery key?

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
    if combos:
        return _find_smart_path(challenges, combos)
    else:
        return _find_dumb_path(challenges)


def _find_smart_path(challenges, combos):
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
    for i, chall in enumerate(CONFIG.CHALLENGE_PREFERENCES):
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


def _find_dumb_path(challenges):
    """Find challenge path without server hints.

    Should be called if the combinations hint is not included by the
    server. This function returns the best path that does not contain
    multiple mutually exclusive challenges.

    :param list challenges: A list of challenges from ACME "challenge"
        server message to be fulfilled by the client in order to prove
        possession of the identifier.

    :returns: List of indices from `challenges`.
    :rtype: list

    """
    # Add logic for a crappy server
    # Choose a DV
    path = []
    for pref_c in CONFIG.CHALLENGE_PREFERENCES:
        for i, offered_challenge in enumerate(challenges):
            if (pref_c == offered_challenge["type"] and
                    is_preferred(offered_challenge["type"], path)):
                path.append((i, offered_challenge["type"]))

    return [i for (i, _) in path]


def is_preferred(offered_challenge_type, path):
    for _, challenge_type in path:
        for mutually_exclusive in CONFIG.EXCLUSIVE_CHALLENGES:
            # Second part is in case we eventually allow multiple names
            # to be challenges at the same time
            if (challenge_type in mutually_exclusive and
                    offered_challenge_type in mutually_exclusive and
                    challenge_type != offered_challenge_type):
                return False

    return True
