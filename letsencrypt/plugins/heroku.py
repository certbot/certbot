"""Herkou plugin."""
import os
import logging
import pipes
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

from subprocess import check_output, CalledProcessError

import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)

def _run_as_user(command, shell=False, dry_run=False):
    # If we need to sudo back, set that up.
    sudo_user = os.environ["SUDO_USER"]

    if sudo_user is None:
        full_command = command
    else:
        su_part = ["sudo", "-u", sudo_user]
        if shell:
            full_command = su_part + ["-s", command]
            shell = False
        else:
            full_command = su_part + command
    
    # Format a loggable version of the command.
    if os.getuid() == 0:
        prompt = "# "
    else:
        prompt = "$ "

    if shell:
        description = prompt + full_command
    else:
        description = prompt + " ".join(map(cmd_quote, full_command))

    # Do it, or don't.
    if dry_run:
        logger.warning("Would run: " + description)
        return None
    else:
        logger.info("Running: " + description)
        return check_output(full_command)

class GitClient:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def run(self, args, skip_if_dry=False):
        dry_run_now = self.dry_run and not skip_if_dry
        return _run_as_user(['git'] + args, dry_run=dry_run_now)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Heroku Authenticator.

    This plugin writes challenge files into the ./public folder, then 
    commits them to git and pushes them to a remote repository. 
    On Heroku, this will deploy the challenge files to the server, where
    they'll be served to Let's Encrypt as needed.

    .. todo:: Support for `~.challenges.TLSSNI01`.

    """
    hidden = False

    description = "Authenticate a Heroku app"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self._root = self.conf("root")
        self._remote = self.conf("remote")
        self._branch = self.conf("branch")
        self._git_client = GitClient(dry_run=self.config.dry_run)

    @classmethod
    def add_parser_arguments(cls, add):
        add("root", default="public", help="Directory containing static assets.")
        add("remote", default="heroku", help="git remote to push to for deployment.")
        add("branch", default="master", help="git branch to push for deployment.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        #if self.config.noninteractive_mode and not self.conf("test-mode"):
        #    raise errors.PluginError("Running manual mode non-interactively is not supported")
        pass

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin requires user's manual intervention in setting "
                "up an HTTP server for solving http-01 challenges and thus "
                "does not need to be run as a privileged process. "
                "Alternatively shows instructions on how to use Python's "
                "built-in HTTP server.")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        # XXX make these configurable
        root = self._root
        remote = self._remote
        branch = self._branch
        
        self._preflight(root=root, remote=remote, branch=branch)
        
        owner = os.stat(root).st_uid
        directory = root + "/" + achalls[0].URI_ROOT_PATH
        
        self._clear_directory(directory=directory)
        for achall in achalls:
            self._write_challenge(achall, directory=directory)
        self._chown_challenges(root=root, directory=directory, owner=owner)
        self._commit(directory=directory)

        self._deploy(remote=remote)

        responses = []
        # TODO: group achalls by the same socket.gethostbyname(_ex)
        # and prompt only once per server (one "echo -n" per domain)
        for achall in achalls:
            responses.append(self._wait_for_challenge_validation(achall))
        return responses
    
    def _preflight(self, root, remote, branch):
        if not os.path.exists(root):
            raise errors.PluginError("The '" + root + "' folder doesn't exist")
        
        # Make sure we're on the right branch
        try:
            output = self._git_client.run(["symbolic-ref", "--short", "-q", "HEAD"], skip_if_dry=True)
            checked_out = output.rstrip()
            if checked_out != branch:
                raise errors.PluginError("Working copy has '" + checked_out +"' checked out, not '" + branch + "'")
        except CalledProcessError:
            raise errors.PluginError("Cannot identify a checked-out git branch")

        # git remote update will fail if there's no such remote, but it's also necessary 
        # for getting the status in the next step.
        try:
            self._git_client.run(["remote", "update", remote], skip_if_dry=True)
        except CalledProcessError:
            raise errors.PluginError("The '" + remote + "' git remote is not configured (use --heroku-remote to set a different one)")

        try:
            self._git_client.run(["diff", "--staged", "--quiet", remote + "/" + branch], skip_if_dry=True)
        except CalledProcessError:
            raise errors.PluginError("The working copy is out of date with the '" + remote + "' remote")

    def _clear_directory(self, directory):
        if os.path.exists(directory):
            shutil.rmtree(directory)

    def _write_challenge(self, achall, directory):
        response, validation = achall.response_and_validation()
        
        if not os.path.exists(directory):
            os.makedirs(directory)

        file = directory + "/" + achall.chall.encode("token")
        with open(file, "w") as validation_file:
            validation_file.write(validation.encode())
    
    def _chown_challenges(self, root, directory, owner):
        while root != os.path.dirname(directory):
            directory = os.path.dirname(directory)
        
        logger.warning("Chowning under " + directory)
        os.chown(directory, owner, -1)
        for (dirpath, dirs, files) in os.walk(directory):
            for file in dirs + files:
                os.chown(os.path.join(dirpath, file), owner, -1)

    def _commit(self, directory):
        self._git_client.run(["add", directory])
        
        commit_message = "Challenges for Let's Encrypt certificate"
        if self.config.staging:
            commit_message += " (testing only)"
        self._git_client.run(["commit", "-m", commit_message])

    def _deploy(self, remote):
        logger.warning("Pushing to '" + remote + "'...")
        self._git_client.run(["push", remote])

    def _wait_for_challenge_validation(self, achall):
        response, validation = achall.response_and_validation()

        logger.warning("Verifying challenge for " + achall.domain + " (Ctrl-C to skip)")
        try:
            while not response.simple_verify(
                    achall.chall, achall.domain,
                    achall.account_key.public_key(), self.config.http01_port):
                time.sleep(10)
        except KeyboardInterrupt:
            pass

        return response

    def _notify_and_wait(self, message):  # pylint: disable=no-self-use
        # TODO: IDisplay wraps messages, breaking the command
        #answer = zope.component.getUtility(interfaces.IDisplay).notification(
        #    message=message, height=25, pause=True)
        sys.stdout.write(message)
        raw_input("Press ENTER to continue")

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        pass
