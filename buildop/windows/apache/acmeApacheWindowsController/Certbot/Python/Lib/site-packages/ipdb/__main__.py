# Copyright (c) 2011-2016 Godefroid Chapelle and ipdb development team
#
# This file is part of ipdb.
# Redistributable under the revised BSD license
# https://opensource.org/licenses/BSD-3-Clause

from __future__ import print_function
import os
import sys

from contextlib import contextmanager

__version__ = '0.13.2'

from IPython import get_ipython
from IPython.core.debugger import BdbQuit_excepthook
from IPython.terminal.ipapp import TerminalIPythonApp
from IPython.terminal.embed import InteractiveShellEmbed
try:
    import configparser
except:
    import ConfigParser as configparser


shell = get_ipython()
if shell is None:
    # Not inside IPython
    # Build a terminal app in order to force ipython to load the
    # configuration
    ipapp = TerminalIPythonApp()
    # Avoid output (banner, prints)
    ipapp.interact = False
    ipapp.initialize(['--no-term-title'])
    shell = ipapp.shell
else:
    # Running inside IPython

    # Detect if embed shell or not and display a message
    if isinstance(shell, InteractiveShellEmbed):
        sys.stderr.write(
            "\nYou are currently into an embedded ipython shell,\n"
            "the configuration will not be loaded.\n\n"
        )

# Let IPython decide about which debugger class to use
# This is especially important for tools that fiddle with stdout
debugger_cls = shell.debugger_cls


def _init_pdb(context=3, commands=[]):
    try:
        p = debugger_cls(context=context)
    except TypeError:
        p = debugger_cls()
    p.rcLines.extend(commands)
    return p


def wrap_sys_excepthook():
    # make sure we wrap it only once or we would end up with a cycle
    #  BdbQuit_excepthook.excepthook_ori == BdbQuit_excepthook
    if sys.excepthook != BdbQuit_excepthook:
        BdbQuit_excepthook.excepthook_ori = sys.excepthook
        sys.excepthook = BdbQuit_excepthook


def set_trace(frame=None, context=None):
    wrap_sys_excepthook()
    if not context:
        context = os.environ.get(
            "IPDB_CONTEXT_SIZE", get_context_from_config()
        )
    if frame is None:
        frame = sys._getframe().f_back
    p = _init_pdb(context).set_trace(frame)
    if p and hasattr(p, 'shell'):
        p.shell.restore_sys_module_state()


def get_context_from_config():
    try:
        parser = get_config()
        return parser.getint("ipdb", "context")
    except (configparser.NoSectionError, configparser.NoOptionError):
        return 3
    except ValueError:
        value = parser.get("ipdb", "context")
        raise ValueError(
            "In %s,  context value [%s] cannot be converted into an integer."
            % (parser.filepath, value)
        )


class ConfigFile(object):
    """
    Filehandle wrapper that adds a "[ipdb]" section to the start of a config
    file so that users don't actually have to manually add a [ipdb] section.
    Works with configparser versions from both Python 2 and 3
    """

    def __init__(self, filepath):
        self.first = True
        with open(filepath) as f:
            self.lines = f.readlines()

    # Python 2.7 (Older dot versions)
    def readline(self):
        try:
            return self.__next__()
        except StopIteration:
            return ''

    # Python 2.7 (Newer dot versions)
    def next(self):
        return self.__next__()

    # Python 3
    def __iter__(self):
        return self

    def __next__(self):
        if self.first:
            self.first = False
            return "[ipdb]\n"
        if self.lines:
            return self.lines.pop(0)
        raise StopIteration


def get_config():
    """
    Get ipdb config file settings.
    All available config files are read.  If settings are in multiple configs,
    the last value encountered wins.  Values specified on the command-line take
    precedence over all config file settings.
    Returns: A ConfigParser object.
    """
    parser = configparser.ConfigParser()

    filepaths = []

    # Low priority goes first in the list
    for cfg_file in ("setup.cfg", ".ipdb"):
        cwd_filepath = os.path.join(os.getcwd(), cfg_file)
        if os.path.isfile(cwd_filepath):
            filepaths.append(cwd_filepath)

    # Medium priority (whenever user wants to set a specific path to config file)
    home = os.getenv("HOME")
    if home:
        default_filepath = os.path.join(home, ".ipdb")
        if os.path.isfile(default_filepath):
            filepaths.append(default_filepath)

    # High priority (default files)
    env_filepath = os.getenv("IPDB_CONFIG")
    if env_filepath and os.path.isfile(env_filepath):
        filepaths.append(env_filepath)

    if filepaths:
        # Python 3 has parser.read_file(iterator) while Python2 has
        # parser.readfp(obj_with_readline)
        try:
            read_func = parser.read_file
        except AttributeError:
            read_func = parser.readfp
        for filepath in filepaths:
            parser.filepath = filepath
            # Users are expected to put an [ipdb] section
            # only if they use setup.cfg
            if filepath.endswith('setup.cfg'):
                with open(filepath) as f:
                    read_func(f)
            else:
                read_func(ConfigFile(filepath))
    return parser


def post_mortem(tb=None):
    wrap_sys_excepthook()
    p = _init_pdb()
    p.reset()
    if tb is None:
        # sys.exc_info() returns (type, value, traceback) if an exception is
        # being handled, otherwise it returns None
        tb = sys.exc_info()[2]
    if tb:
        p.interaction(None, tb)


def pm():
    post_mortem(sys.last_traceback)


def run(statement, globals=None, locals=None):
    _init_pdb().run(statement, globals, locals)


def runcall(*args, **kwargs):
    return _init_pdb().runcall(*args, **kwargs)


def runeval(expression, globals=None, locals=None):
    return _init_pdb().runeval(expression, globals, locals)


@contextmanager
def launch_ipdb_on_exception():
    try:
        yield
    except Exception:
        e, m, tb = sys.exc_info()
        print(m.__repr__(), file=sys.stderr)
        post_mortem(tb)
    finally:
        pass


_usage = """\
usage: python -m ipdb [-c command] ... pyfile [arg] ...

Debug the Python program given by pyfile.

Initial commands are read from .pdbrc files in your home directory
and in the current directory, if they exist.  Commands supplied with
-c are executed after commands from .pdbrc files.

To let the script run until an exception occurs, use "-c continue".
To let the script run up to a given line X in the debugged file, use
"-c 'until X'"
ipdb version %s.""" % __version__


def main():
    import traceback
    import sys
    import getopt

    try:
        from pdb import Restart
    except ImportError:
        class Restart(Exception):
            pass

    opts, args = getopt.getopt(sys.argv[1:], 'hc:', ['help', 'command='])

    commands = []
    for opt, optarg in opts:
        if opt in ['-h', '--help']:
            print(_usage)
            sys.exit()
        elif opt in ['-c', '--command']:
            commands.append(optarg)

    if not args:
        print(_usage)
        sys.exit(2)

    mainpyfile = args[0]     # Get script filename
    if not os.path.exists(mainpyfile):
        print('Error:', mainpyfile, 'does not exist')
        sys.exit(1)

    sys.argv = args     # Hide "pdb.py" from argument list

    # Replace pdb's dir with script's dir in front of module search path.
    sys.path[0] = os.path.dirname(mainpyfile)

    # Note on saving/restoring sys.argv: it's a good idea when sys.argv was
    # modified by the script being debugged. It's a bad idea when it was
    # changed by the user from the command line. There is a "restart" command
    # which allows explicit specification of command line arguments.
    pdb = _init_pdb(commands=commands)
    while 1:
        try:
            pdb._runscript(mainpyfile)
            if pdb._user_requested_quit:
                break
            print("The program finished and will be restarted")
        except Restart:
            print("Restarting", mainpyfile, "with arguments:")
            print("\t" + " ".join(sys.argv[1:]))
        except SystemExit:
            # In most cases SystemExit does not warrant a post-mortem session.
            print("The program exited via sys.exit(). Exit status: ", end='')
            print(sys.exc_info()[1])
        except:
            traceback.print_exc()
            print("Uncaught exception. Entering post mortem debugging")
            print("Running 'cont' or 'step' will restart the program")
            t = sys.exc_info()[2]
            pdb.interaction(None, t)
            print("Post mortem debugger finished. The " + mainpyfile +
                  " will be restarted")


if __name__ == '__main__':
    main()
