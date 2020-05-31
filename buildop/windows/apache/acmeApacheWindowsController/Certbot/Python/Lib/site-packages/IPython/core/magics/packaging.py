"""Implementation of packaging-related magic functions.
"""
#-----------------------------------------------------------------------------
#  Copyright (c) 2018 The IPython Development Team.
#
#  Distributed under the terms of the Modified BSD License.
#
#  The full license is in the file COPYING.txt, distributed with this software.
#-----------------------------------------------------------------------------

import os
import re
import shlex
import sys

from IPython.core.magic import Magics, magics_class, line_magic


def _is_conda_environment():
    """Return True if the current Python executable is in a conda env"""
    # TODO: does this need to change on windows?
    conda_history = os.path.join(sys.prefix, 'conda-meta', 'history')
    return os.path.exists(conda_history)


def _get_conda_executable():
    """Find the path to the conda executable"""
    # Check if there is a conda executable in the same directory as the Python executable.
    # This is the case within conda's root environment.
    conda = os.path.join(os.path.dirname(sys.executable), 'conda')
    if os.path.isfile(conda):
        return conda

    # Otherwise, attempt to extract the executable from conda history.
    # This applies in any conda environment.
    R = re.compile(r"^#\s*cmd:\s*(?P<command>.*conda)\s[create|install]")
    with open(os.path.join(sys.prefix, 'conda-meta', 'history')) as f:
        for line in f:
            match = R.match(line)
            if match:
                return match.groupdict()['command']
    
    # Fallback: assume conda is available on the system path.
    return "conda"


CONDA_COMMANDS_REQUIRING_PREFIX = {
    'install', 'list', 'remove', 'uninstall', 'update', 'upgrade',
}
CONDA_COMMANDS_REQUIRING_YES = {
    'install', 'remove', 'uninstall', 'update', 'upgrade',
}
CONDA_ENV_FLAGS = {'-p', '--prefix', '-n', '--name'}
CONDA_YES_FLAGS = {'-y', '--y'}


@magics_class
class PackagingMagics(Magics):
    """Magics related to packaging & installation"""

    @line_magic
    def pip(self, line):
        """Run the pip package manager within the current kernel.

        Usage:
          %pip install [pkgs]
        """
        self.shell.system(' '.join([sys.executable, '-m', 'pip', line]))
        print("Note: you may need to restart the kernel to use updated packages.")

    @line_magic
    def conda(self, line):
        """Run the conda package manager within the current kernel.
        
        Usage:
          %conda install [pkgs]
        """
        if not _is_conda_environment():
            raise ValueError("The python kernel does not appear to be a conda environment.  "
                             "Please use ``%pip install`` instead.")
        
        conda = _get_conda_executable()
        args = shlex.split(line)
        command = args[0]
        args = args[1:]
        extra_args = []

        # When the subprocess does not allow us to respond "yes" during the installation,
        # we need to insert --yes in the argument list for some commands
        stdin_disabled = getattr(self.shell, 'kernel', None) is not None
        needs_yes = command in CONDA_COMMANDS_REQUIRING_YES
        has_yes = set(args).intersection(CONDA_YES_FLAGS)
        if stdin_disabled and needs_yes and not has_yes:
            extra_args.append("--yes")

        # Add --prefix to point conda installation to the current environment
        needs_prefix = command in CONDA_COMMANDS_REQUIRING_PREFIX
        has_prefix = set(args).intersection(CONDA_ENV_FLAGS)
        if needs_prefix and not has_prefix:
            extra_args.extend(["--prefix", sys.prefix])

        self.shell.system(' '.join([conda, command] + extra_args + args))
        print("\nNote: you may need to restart the kernel to use updated packages.")
