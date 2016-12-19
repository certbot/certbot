"""Facilities for implementing hooks that call shell commands."""
from __future__ import print_function

import logging
import os

from subprocess import Popen, PIPE

from certbot import util

logger = logging.getLogger(__name__)

def validate_hooks(config):
    """Check hook commands are executable."""
    for hook in (config.pre_hook, config.post_hook, config.renew_hook,):
        validate_hook(hook)

def validate_hook(shell_cmd):
    """Check that a command provided as a hook is plausibly executable.

    If shell_cmd is None, no validation is done.

    :param shell_cmd: command to execute in a shell

    :raises .errors.CommandNotExecutable: if a path is given for command
        but it isn't a path to an executable

    :raises .errors.CommandNotFound: if the command is not found

    """
    if shell_cmd is not None:
        util.verify_exe_exists(shell_cmd.split(None, 1)[0])

def pre_hook(config):
    "Run pre-hook if it's defined and hasn't been run."
    if config.pre_hook and not pre_hook.already:
        logger.info("Running pre-hook command: %s", config.pre_hook)
        _run_hook(config.pre_hook)
    pre_hook.already = True

pre_hook.already = False

def post_hook(config, final=False):
    """Run post hook if defined.

    If the verb is renew, we might have more certs to renew, so we wait until
    we're called with final=True before actually doing anything.
    """
    if config.post_hook:
        if not pre_hook.already:
            logger.info("No renewals attempted, so not running post-hook")
            if config.verb != "renew":
                logger.warning("Sanity failure in renewal hooks")
            return
        if final or config.verb != "renew":
            logger.info("Running post-hook command: %s", config.post_hook)
            _run_hook(config.post_hook)

def renew_hook(config, domains, lineage_path):
    "Run post-renewal hook if defined."
    if config.renew_hook:
        if not config.dry_run:
            os.environ["RENEWED_DOMAINS"] = " ".join(domains)
            os.environ["RENEWED_LINEAGE"] = lineage_path
            _run_hook(config.renew_hook)
        else:
            logger.warning("Dry run: skipping renewal hook command: %s", config.renew_hook)


def _run_hook(shell_cmd):
    """Run a hook command.

    :returns: stderr if there was any"""

    err, _ = execute(shell_cmd)
    return err


def execute(shell_cmd):
    """Run a command.

    :returns: `tuple` (`str` stderr, `str` stdout)"""

    # universal_newlines causes Popen.communicate()
    # to return str objects instead of bytes in Python 3
    cmd = Popen(shell_cmd, shell=True, stdout=PIPE,
                stderr=PIPE, universal_newlines=True)
    out, err = cmd.communicate()
    if cmd.returncode != 0:
        logger.error('Hook command "%s" returned error code %d',
                     shell_cmd, cmd.returncode)
    if err:
        base_cmd = os.path.basename(shell_cmd.split(None, 1)[0])
        logger.error('Error output from %s:\n%s', base_cmd, err)
    return (err, out)
