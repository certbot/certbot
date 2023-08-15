""" Utility functions for certbot-apache plugin """
import atexit
import binascii
import fnmatch
import logging
import re
import subprocess
import sys
from contextlib import ExitStack
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

from certbot import errors
from certbot import util
from certbot.compat import os

if sys.version_info >= (3, 9):  # pragma: no cover
    import importlib.resources as importlib_resources
else:
    import importlib_resources


logger = logging.getLogger(__name__)


def get_mod_deps(mod_name: str) -> List[str]:
    """Get known module dependencies.

    .. note:: This does not need to be accurate in order for the client to
        run.  This simply keeps things clean if the user decides to revert
        changes.
    .. warning:: If all deps are not included, it may cause incorrect parsing
        behavior, due to enable_mod's shortcut for updating the parser's
        currently defined modules (`.ApacheParser.add_mod`)
        This would only present a major problem in extremely atypical
        configs that use ifmod for the missing deps.

    """
    deps = {
        "ssl": ["setenvif", "mime"]
    }
    return deps.get(mod_name, [])


def get_file_path(vhost_path: str) -> Optional[str]:
    """Get file path from augeas_vhost_path.

    Takes in Augeas path and returns the file name

    :param str vhost_path: Augeas virtual host path

    :returns: filename of vhost
    :rtype: str

    """
    if not vhost_path or not vhost_path.startswith("/files/"):
        return None

    return _split_aug_path(vhost_path)[0]


def get_internal_aug_path(vhost_path: str) -> str:
    """Get the Augeas path for a vhost with the file path removed.

    :param str vhost_path: Augeas virtual host path

    :returns: Augeas path to vhost relative to the containing file
    :rtype: str

    """
    return _split_aug_path(vhost_path)[1]


def _split_aug_path(vhost_path: str) -> Tuple[str, str]:
    """Splits an Augeas path into a file path and an internal path.

    After removing "/files", this function splits vhost_path into the
    file path and the remaining Augeas path.

    :param str vhost_path: Augeas virtual host path

    :returns: file path and internal Augeas path
    :rtype: `tuple` of `str`

    """
    # Strip off /files
    file_path = vhost_path[6:]
    internal_path: List[str] = []

    # Remove components from the end of file_path until it becomes valid
    while not os.path.exists(file_path):
        file_path, _, internal_path_part = file_path.rpartition("/")
        internal_path.append(internal_path_part)

    return file_path, "/".join(reversed(internal_path))


def parse_define_file(filepath: str, varname: str) -> Dict[str, str]:
    """ Parses Defines from a variable in configuration file

    :param str filepath: Path of file to parse
    :param str varname: Name of the variable

    :returns: Dict of Define:Value pairs
    :rtype: `dict`

    """
    return_vars: Dict[str, str] = {}
    # Get list of words in the variable
    a_opts = util.get_var_from_file(varname, filepath).split()
    for i, v in enumerate(a_opts):
        # Handle Define statements and make sure it has an argument
        if v == "-D" and len(a_opts) >= i+2:
            var_parts = a_opts[i+1].partition("=")
            return_vars[var_parts[0]] = var_parts[2]
        elif len(v) > 2 and v.startswith("-D"):
            # Found var with no whitespace separator
            var_parts = v[2:].partition("=")
            return_vars[var_parts[0]] = var_parts[2]
    return return_vars


def unique_id() -> str:
    """ Returns an unique id to be used as a VirtualHost identifier"""
    return binascii.hexlify(os.urandom(16)).decode("utf-8")


def included_in_paths(filepath: str, paths: Iterable[str]) -> bool:
    """
    Returns true if the filepath is included in the list of paths
    that may contain full paths or wildcard paths that need to be
    expanded.

    :param str filepath: Filepath to check
    :param list paths: List of paths to check against

    :returns: True if included
    :rtype: bool
    """
    return any(fnmatch.fnmatch(filepath, path) for path in paths)


def parse_defines(define_cmd: List[str]) -> Dict[str, str]:
    """
    Gets Defines from httpd process and returns a dictionary of
    the defined variables.

    :param list define_cmd: httpd command to dump defines

    :returns: dictionary of defined variables
    :rtype: dict
    """

    variables: Dict[str, str] = {}
    matches = parse_from_subprocess(define_cmd, r"Define: ([^ \n]*)")
    try:
        matches.remove("DUMP_RUN_CFG")
    except ValueError:
        return {}

    for match in matches:
        # Value could also contain = so split only once
        parts = match.split('=', 1)
        value = parts[1] if len(parts) == 2 else ''
        variables[parts[0]] = value

    return variables


def parse_includes(inc_cmd: List[str]) -> List[str]:
    """
    Gets Include directives from httpd process and returns a list of
    their values.

    :param list inc_cmd: httpd command to dump includes

    :returns: list of found Include directive values
    :rtype: list of str
    """

    return parse_from_subprocess(inc_cmd, r"\(.*\) (.*)")


def parse_modules(mod_cmd: List[str]) -> List[str]:
    """
    Get loaded modules from httpd process, and return the list
    of loaded module names.

    :param list mod_cmd: httpd command to dump loaded modules

    :returns: list of found LoadModule module names
    :rtype: list of str
    """

    return parse_from_subprocess(mod_cmd, r"(.*)_module")


def parse_from_subprocess(command: List[str], regexp: str) -> List[str]:
    """Get values from stdout of subprocess command

    :param list command: Command to run
    :param str regexp: Regexp for parsing

    :returns: list parsed from command output
    :rtype: list

    """
    stdout = _get_runtime_cfg(command)
    return re.compile(regexp).findall(stdout)


def _get_runtime_cfg(command: List[str]) -> str:
    """
    Get runtime configuration info.

    :param command: Command to run

    :returns: stdout from command

    """
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
            env=util.env_no_snap_for_external_calls())
        stdout, stderr = proc.stdout, proc.stderr

    except (OSError, ValueError):
        logger.error(
            "Error running command %s for runtime parameters!%s",
            command, os.linesep)
        raise errors.MisconfigurationError(
            "Error accessing loaded Apache parameters: {0}".format(
                command))
    # Small errors that do not impede
    if proc.returncode != 0:
        logger.warning("Error in checking parameter list: %s", stderr)
        raise errors.MisconfigurationError(
            "Apache is unable to check whether or not the module is "
            "loaded because Apache is misconfigured.")

    return stdout


def find_ssl_apache_conf(prefix: str) -> str:
    """
    Find a TLS Apache config file in the dedicated storage.
    :param str prefix: prefix of the TLS Apache config file to find
    :return: the path the TLS Apache config file
    :rtype: str
    """
    file_manager = ExitStack()
    atexit.register(file_manager.close)
    ref = importlib_resources.files("certbot_apache").joinpath(
        "_internal", "tls_configs", "{0}-options-ssl-apache.conf".format(prefix))
    return str(file_manager.enter_context(importlib_resources.as_file(ref)))
