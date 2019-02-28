"""This module warns for usage of deprecated letsencrypt-auto"""
import os
import sys
import logging
import logging.handlers

from certbot.cli import (
    cli_command,
    LEAUTO
)

logger = logging.getLogger(__name__)


def possible_deprecation_warning(config):
    "A deprecation warning for users with the old, not-self-upgrading letsencrypt-auto."
    if cli_command != LEAUTO:
        return
    if config.no_self_upgrade:
        # users setting --no-self-upgrade might be hanging on a client version like 0.3.0
        # or 0.5.0 which is the new script, but doesn't set CERTBOT_AUTO; they don't
        # need warnings
        return
    if "CERTBOT_AUTO" not in os.environ:
        logger.warning("You are running with an old copy of letsencrypt-auto"
            " that does not receive updates, and is less reliable than more"
            " recent versions. The letsencrypt client has also been renamed"
            " to Certbot. We recommend upgrading to the latest certbot-auto"
            " script, or using native OS packages.")
        logger.debug("Deprecation warning circumstances: %s / %s", sys.argv[0], os.environ)
