"""Facilities for implementing hooks that call shell commands."""
from __future__ import print_function

import logging
import os

from subprocess import Popen, PIPE

from certbot import errors

logger = logging.getLogger(__name__)

def validate_hooks(config):
    """Check hook commands are executable."""
    _validate_hook(config.pre_hook, "pre")
    _validate_hook(config.post_hook, "post")
    _validate_hook(config.renew_hook, "renew")

def _prog(shell_cmd):
    """Extract the program run by a shell command"""
    cmd = _which(shell_cmd)
    return os.path.basename(cmd) if cmd else None

def _validate_hook(shell_cmd, hook_name):
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

    cmd = Popen(shell_cmd, shell=True, stdout=PIPE, stderr=PIPE, stdin=PIPE)
    _out, err = cmd.communicate()
    if cmd.returncode != 0:
        logger.error('Hook command "%s" returned error code %d', shell_cmd, cmd.returncode)
    if err:
        logger.error('Error output from %s:\n%s', _prog(shell_cmd), err)

def _is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def _which(program):
    """Test if program is in the path."""
    # Borrowed from:
    # https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    # XXX May need more porting to handle .exe extensions on Windows

    fpath, _fname = os.path.split(program)
    if fpath:
        if _is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if _is_exe(exe_file):
                return exe_file

    return None
