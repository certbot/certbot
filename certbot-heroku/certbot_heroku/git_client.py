from certbot_heroku.command import Command

class GitClient:
    def __init__(self, logger, dry_run=False):
        self.logger = logger
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

        output = command.capture(logger=self.logger)
        return output.rstrip()
    
    """
    Updates the indicated remote in the working copy's branch. Doesn't actually
    affect the checked-out code; this is more like a fetch than a pull.
    """
    def update_remote(self, remote):
        command = self.git("remote", "update", remote)
        command.on_returncode(1, raises=GitClient.NoRemoteError)
        
        command.run(logger=self.logger)
    
    """
    Returns True if the working copy and the (local cached copy of the) remote
    are on the same commit and there are no staged changes, False otherwise.
    """
    def is_up_to_date(self, branch, remote):
        command = self.git("diff", "--staged", "--quiet", remote + "/" + branch)
        
        command.on_returncode(0, returns=True)
        command.on_returncode(1, returns=False)
        
        return command.run(logger=self.logger)
    
    """
    Adds the specified file (or contents of the specified directory) to the
    working copy's index.
    """
    def stage_file(self, path):
        self.git("add", path).run(logger=self.logger, dry_run=self.dry_run)
    
    """
    Commits the working copy's staged changes with the indicated message.
    """
    def commit(self, message):
        self.git("commit", "-m", message).run(logger=self.logger, dry_run=self.dry_run)
    
    """
    Pushes recent commits to the indicated remote.
    """
    def push_to_remote(self, remote):
        self.git("push", remote).run(logger=self.logger, dry_run=self.dry_run)
    
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
