"""Facilities for implementing hooks that call shell commands."""
from __future__ import print_function

import logging
import os

from subprocess import Popen, PIPE

from certbot import errors
from certbot import util

from certbot.plugins import util as plug_util

logger = logging.getLogger(__name__)

def validate_hooks(config):
    """Check hook commands are executable."""
    validate_hook(config.pre_hook, "pre")
    validate_hook(config.post_hook, "post")
    validate_hook(config.renew_hook, "renew")

def _prog(shell_cmd):
    """Extract the program run by a shell command"""
    cmd = util.which(shell_cmd)
    if not cmd:
        plug_util.path_surgery(shell_cmd)
        cmd = util.which(shell_cmd)

    return os.path.basename(cmd) if cmd else None


def validate_hook(shell_cmd, hook_name):
    """Check that a command provided as a hook is plausibly executable.

    :raises .errors.HookCommandNotFound: if the command is not found
    """
    if shell_cmd:
        cmd = shell_cmd.split(None, 1)[0]
        if not _prog(cmd):
            path = os.environ["PATH"]
            msg = "Unable to find {2}-hook command {0} in the PATH.\n(PATH is {1})".format(
                cmd, path, hook_name)
            raise errors.HookCommandNotFound(msg)

def pre_hook(config):
    "Run pre-hook if it's defined and hasn't been run."
    cmd = config.pre_hook
    if cmd and cmd not in pre_hook.already:
        logger.info("Running pre-hook command: %s", cmd)
        _run_hook(cmd)
        pre_hook.already[cmd] = True
    elif cmd:
        logger.info("Pre-hook command already run, skipping: %s", cmd)

pre_hook.already = {}


def post_hook(config):
    """Run post hook if defined.

    If the verb is renew, we might have more certs to renew, so we wait until
    run_saved_post_hooks() is called.
    """

    cmd = config.post_hook
    # In the "renew" case, we save these up to run at the end
    if config.verb == "renew":
        if cmd and cmd not in post_hook.eventually:
            post_hook.eventually.append(cmd)
    # certonly / run
    elif cmd:
        logger.info("Running post-hook command: %s", cmd)
        _run_hook(cmd)

post_hook.eventually = []

def run_saved_post_hooks():
    """Run any post hooks that were saved up in the course of the 'renew' verb"""
    for cmd in post_hook.eventually:
        logger.info("Running post-hook command: %s", cmd)
        _run_hook(cmd)
    if len(post_hook.eventually) == 0:
        logger.info("No renewals attempted, so not running post-hook")

def renew_hook(config, domains, lineage_path):
    """Run post-renewal hook if defined."""
    if config.renew_hook:
        if not config.dry_run:
            os.environ["RENEWED_DOMAINS"] = " ".join(domains)
            os.environ["RENEWED_LINEAGE"] = lineage_path
            logger.info("Running renew-hook command: %s", config.renew_hook)
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

    cmd = Popen(shell_cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = cmd.communicate()
    if cmd.returncode != 0:
        logger.error('Hook command "%s" returned error code %d',
                     shell_cmd, cmd.returncode)
    if err:
        logger.error('Error output from %s:\n%s', _prog(shell_cmd), err)
    return (err, out)

