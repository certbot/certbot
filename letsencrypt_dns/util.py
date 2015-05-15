"""Utilities."""
import argparse


def split_tsig_keys(packed):
    """Returns the unpacked TSIG key name, secret, and a list of domains from
    the argument format.

    :param str packed: TSIG key in the format "key-name,key-secret,domains+"

    :returns: A tuple of key name, secret, and a list of domains
    :rtype: tuple

    :raises argparse.ArgumentTypeError: Packed TSIG key is in incorrect format.

    """
    # if --dns-tsig-keys "" called... you never know
    if not packed:
        raise argparse.ArgumentTypeError("No TSIG keys provided.")
    unpacked = packed.split(",")
    if len(unpacked) < 3:
        raise argparse.ArgumentTypeError(
            "Provided TSIG key is in incorrect format.")
    return unpacked[0], unpacked[1], unpacked[2:]
