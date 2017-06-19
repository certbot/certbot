"""Runs Certbot."""
import logging
import sys

import certbot.main


logger = logging.getLogger(__name__)


def main():
    """Runs Certbot, logs any returned message, and calls sys.exit.

    If certbot.main.main returns a non-empty string, it is passed to
    sys.exit causing a non-zero status code and the string to be
    printed to stderr.

    """
    err_string = certbot.main.main()
    if err_string:
        logger.debug('Exiting with message %s', err_string)
    sys.exit(err_string)


if __name__ == '__main__':
    main()
