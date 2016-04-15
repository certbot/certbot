"""Heroku plugin."""
import os
import logging
import shutil
import time

import zope.component
from acme import challenges
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common

# Used by the Command class
import subprocess
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

logger = logging.getLogger(__name__)

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
        return ("This plugin writes challenge files into a directory where "
                "they will be served from (by default, './public'), "
                "commits them to a git branch (by default, 'master'), "
                "and pushes them to a remote (by default, 'heroku'). "
                "It then waits for the challenge files to appear on the live "
                "site before telling Let's Encrypt to check them. To use it, "
                "you must be in a git working copy of the website, with the "
                "master branch checked out and on the same commit as the "
                "remote repository's version of the branch.")
    
    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]
    
    def perform(self, achalls):  # pylint: disable=missing-docstring
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
        
        logger.warning("Committing and pushing challenges to Heroku...")
        self._commit(directory=directory)
        self._deploy(remote=remote)
        logger.warning(" ")

        responses = []
        for achall in achalls:
            responses.append(self._wait_for_challenge_validation(achall))
        return responses
    
    def _preflight(self, root, remote, branch):
        if not os.path.exists(root):
            raise errors.PluginError("The '" + root + "' folder doesn't exist")
        
        try:
            # Make sure we're on the right branch
            current = self._git_client.checked_out_branch()
            if current != branch:
                raise errors.PluginError("Working copy has '" + current +"' checked out, not '" + branch + "'")

            # git remote update will fail if there's no such remote, but it's also necessary
            # for is_up_to_date to actually give the right answer.
            self._git_client.update_remote(remote)

            # Now make sure the branch is up to date
            if not self._git_client.is_up_to_date(remote=remote, branch=branch):
                raise errors.PluginError("The working copy is out of date with the '" + remote + "' remote")
        
        except GitClient.Error as error:
            raise errors.PluginError(str(error))
    
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

        os.chown(directory, owner, -1)
        for (dirpath, dirs, files) in os.walk(directory):
            for file in dirs + files:
                os.chown(os.path.join(dirpath, file), owner, -1)

    def _commit(self, directory):
        self._git_client.stage_file(directory)
    
        commit_message = "Challenges for Let's Encrypt certificate"
        if self.config.staging:
            commit_message += " (testing only)"
        self._git_client.commit(message=commit_message)
    
    def _deploy(self, remote):
        logger.debug("Pushing to '" + remote + "'...")
        self._git_client.push_to_remote(remote)
        
    def _wait_for_challenge_validation(self, achall):
        response, validation = achall.response_and_validation()
        
        logger.warning("Verifying challenge for " + achall.domain + ". This might take a few minutes if your app is restarting. (Ctrl-C to skip.)")
        try:
            while not response.simple_verify(
                    achall.chall, achall.domain,
                    achall.account_key.public_key(), self.config.http01_port):
                time.sleep(10)
        except KeyboardInterrupt:
            pass

        return response

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        pass

class Command(object):
    def __init__(self, *arguments):
        self.arguments = arguments
        self._returncodes = {}
        
        self.on_returncode(0, returns=None)
        self.on_returncode(None, raises=Command.UnhandledProcessError)
    
    def add_returncode_handler(self, returncode, handler):
        self._returncodes[returncode] = handler
    
    def on_returncode(self, returncode, returns = None, raises = None):
        if raises:
            def make_and_raise(process, returncode):
                raise raises(process, returncode)
            handler = make_and_raise
        else:
            # Use returns
            handler = lambda p, c: returns
        
        self.add_returncode_handler(returncode, handler)
    
    def handler_for_returncode(self, returncode):
        if returncode in self._returncodes:
            return self._returncodes[returncode]
        else:
            return self._returncodes[None]

    """
    If the current environment variables indicate the current process was
    launched using `sudo`, returns a modified version of the command
    which uses `sudo` to run it as the original user. Otherwise, returns
    the command unmodified.
    """
    def resudoed(self):
        # If we need to sudo back, set that up.
        sudo_user = os.environ["SUDO_USER"]

        if sudo_user is None:
            return self
        else:
            return Command("sudo", "-u", sudo_user, *self.arguments)

    """
    Converts the command to an equivalent shell command, including a $ or #
    character.
    """
    def __str__(self):
        if os.getuid() == 0:
            prompt = "# "
        else:
            prompt = "$ "

        return prompt + " ".join(map(cmd_quote, self.arguments))

    """
    Starts a command, returning the resulting Command.Process object.
    """
    def start(self):
        logger.info("Running: " + str(self))
        return Command.Process(self)

    """
    Runs the command, logging its output.
    """
    def run(self, dry_run=False):
        if dry_run:
            logger.warning("Would run: " + str(self))
            return self.handler_for_returncode(0)(None, 0)
        else:
            process = self.start()
            for line in process.lines:
                logger.info("Output: " + line.rstrip())
            return process.finish()
    
    """
    Runs the command, returning a string containing its output on stdout.
    """
    def capture(self):
        process = self.start()
        
        output = ""
        for line in process.lines:
            output += line
        
        process.finish()
        return output
    
    """
    Represents a running process for a command. Has a `command` property
    and a `lines` property; the latter can be looped over to retrieve each line
    of output as they are emitted.
    """
    class Process:
        def __init__(self, command):
            self.command = command
            self._process = subprocess.Popen(self.command.arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
            self.lines = iter(self._process.stdout.readline, '')
        
        """
        Waits for the process to finish, then runs the appropriate returncode handler
        and returns its value.
        """
        def finish(self):
            self._process.wait()
            
            code = self._process.returncode
            handler = self.command.handler_for_returncode(code)
            return handler(self, code)
        
    """
    Represents any error caused by a returncode.
    """
    class ProcessError(Exception):
        def __init__(self, process, returncode):
            self.process = process
            self.returncode = returncode
    
    """
    Represents any error caused by an unexpected returncode.
    """
    class UnhandledProcessError(ProcessError):
        def __str__(self):
            return "The command " + str(self.process.command) + " failed with error code " + self.returncode + "."
        
class GitClient:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
    
    """
    Builds a git command with the provided arguments.
    """
    def git(self, *args):
        command = Command('git', *args).resudoed()
        command.on_returncode(128, raises=GitClient.NoRepositoryError)
        return command

    """
    Determines the branch that the working copy in the current working directory
    has checked out.
    """
    def checked_out_branch(self):
        command = self.git("symbolic-ref", "--short", "-q", "HEAD")
        command.on_returncode(1, raises=GitClient.DetachedHeadError)

        output = command.capture()
        return output.rstrip()
    
    """
    Updates the indicated remote in the working copy's branch. Doesn't actually
    affect the checked-out code; this is more like a fetch than a pull.
    """
    def update_remote(self, remote):
        # XXX how can I quiet this?
        command = self.git("remote", "update", remote)
        command.on_returncode(1, raises=GitClient.NoRemoteError)
        
        command.run()
    
    """
    Returns True if the working copy and the (local cached copy of the) remote
    are on the same commit and there are no staged changes, False otherwise.
    """
    def is_up_to_date(self, branch, remote):
        command = self.git("diff", "--staged", "--quiet", remote + "/" + branch)
        
        command.on_returncode(0, returns=True)
        command.on_returncode(1, returns=False)
        
        return command.run()
    
    """
    Adds the specified file (or contents of the specified directory) to the
    working copy's index.
    """
    def stage_file(self, path):
        self.git("add", path).run(dry_run=self.dry_run)
    
    """
    Commits the working copy's staged changes with the indicated message.
    """
    def commit(self, message):
        self.git("commit", "-m", message).run(dry_run=self.dry_run)
    
    """
    Pushes recent commits to the indicated remote.
    """
    def push_to_remote(self, remote):
        self.git("push", remote).run(dry_run=self.dry_run)
    
    class Error(Command.ProcessError):
        pass
    
    class NoRepositoryError(Error):
        def __str__(self):
            return "The current directory does not appear to be in a git repository."
    
    class NoRemoteError(Error):
        def __str__(self):
            return "The git repository does not appear to have a remote named '" + self.process.command.arguments[-1] + "'. (Use --heroku-remote to set a different one.)"
    
    class DetachedHeadError(Error):
        def __str__(self):
            return "The git repository appears to have a detached HEAD, so there is no branch checked out."
