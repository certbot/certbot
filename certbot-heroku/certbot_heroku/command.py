import os
import subprocess
import errno

try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

class Command(object):
    def __init__(self, *arguments):
        self.arguments = arguments
        self._returncodes = {}
        
        self.on_returncode(0, returns=None)
        self.on_returncode(None, raises=Command.UnhandledProcessError)
    
    """
    Add a function which will be called for a given return code to generate
    a return value for Command.Process.finish() or Command.run(). If 
    returncode=None, it will be used for all unhandled codes. If 
    there is already a handler for this returncode, it will be replaced.
    """
    def add_returncode_handler(self, returncode, handler):
        self._returncodes[returncode] = handler
    
    """
    Handle a return code by returning the indicated value or raising the 
    indicated error. `raises` can be either an Exception subclass or a 
    function; in either case, it must be callable with (process, returncode).
    If returncode=None, it will be used for all unhandled codes. If 
    there is already a handler for this returncode, it will be replaced.
    """
    def on_returncode(self, returncode, returns = None, raises = None):
        if raises:
            def make_and_raise(process, returncode):
                raise raises(process, returncode)
            handler = make_and_raise
        else:
            # Use returns
            handler = lambda p, c: returns
        
        self.add_returncode_handler(returncode, handler)
    
    """
    Returns the handler for the given returncode.
    """
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
    def start(self, logger):
        logger.info("Running: " + str(self))
        try:
            return Command.Process(self)
        except OSError as error:
            if error.errorcode == errno.ENOENT:
                raise NotInstalledError(command=self)
            else:
                raise

    """
    Runs the command, logging its output.
    """
    def run(self, logger, dry_run=False):
        if dry_run:
            logger.warning("Would run: " + str(self))
            return self.handler_for_returncode(0)(None, 0)
        else:
            process = self.start(logger=logger)
            for line in process.lines:
                logger.info("Output: " + line.rstrip())
            return process.finish()
    
    """
    Runs the command, returning a string containing its output on stdout.
    """
    def capture(self, logger):
        process = self.start(logger=logger)
        
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
    
    class NotInstalledError(Exception):
        def __init__(self, command):
            self.command = command
        
        def __str__(self):
            return "The command " + str(self.command) + " is not installed."
