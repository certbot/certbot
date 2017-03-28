"""Provides Tab completion when prompting users for a path."""
import glob
# readline module is not available on all systems
try:
    import readline
except ImportError:
    import certbot.display.dummy_readline as readline  # type: ignore


class Completer(object):
    """Provides Tab completion when prompting users for a path.

    This class is meant to be used with readline to provide Tab
    completion for users entering paths. The complete method can be
    passed to readline.set_completer directly, however, this function
    works best as a context manager. For example:

    with Completer():
        raw_input()

    In this example, Tab completion will be available during the call to
    raw_input above, however, readline will be restored to its previous
    state when exiting the body of the with statement.

    """

    def __init__(self):
        self._iter = self._original_completer = self._original_delims = None

    def complete(self, text, state):
        """Provides path completion for use with readline.

        :param str text: text to offer completions for
        :param int state: which completion to return

        :returns: possible completion for text or ``None`` if all
            completions have been returned
        :rtype: str

        """
        if state == 0:
            self._iter = glob.iglob(text + '*')
        return next(self._iter, None)

    def __enter__(self):
        self._original_completer = readline.get_completer()
        self._original_delims = readline.get_completer_delims()

        readline.set_completer(self.complete)
        readline.set_completer_delims(' \t\n;')

        # readline can be implemented using GNU readline or libedit
        # which have different configuration syntax
        if 'libedit' in readline.__doc__:
            readline.parse_and_bind('bind ^I rl_complete')
        else:
            readline.parse_and_bind('tab: complete')

    def __exit__(self, unused_type, unused_value, unused_traceback):
        readline.set_completer_delims(self._original_delims)
        readline.set_completer(self._original_completer)
