from __future__ import print_function
import sys
import os

from jedi._compatibility import find_module, cast_path, force_unicode, \
    iter_modules, all_suffixes
from jedi.inference.compiled import access
from jedi import parser_utils


def get_sys_path():
    return list(map(cast_path, sys.path))


def load_module(inference_state, **kwargs):
    return access.load_module(inference_state, **kwargs)


def get_compiled_method_return(inference_state, id, attribute, *args, **kwargs):
    handle = inference_state.compiled_subprocess.get_access_handle(id)
    return getattr(handle.access, attribute)(*args, **kwargs)


def create_simple_object(inference_state, obj):
    return access.create_access_path(inference_state, obj)


def get_module_info(inference_state, sys_path=None, full_name=None, **kwargs):
    """
    Returns Tuple[Union[NamespaceInfo, FileIO, None], Optional[bool]]
    """
    if sys_path is not None:
        sys.path, temp = sys_path, sys.path
    try:
        return find_module(full_name=full_name, **kwargs)
    except ImportError:
        return None, None
    finally:
        if sys_path is not None:
            sys.path = temp


def list_module_names(inference_state, search_path):
    return [
        force_unicode(name)
        for module_loader, name, is_pkg in iter_modules(search_path)
    ]


def get_builtin_module_names(inference_state):
    return list(map(force_unicode, sys.builtin_module_names))


def _test_raise_error(inference_state, exception_type):
    """
    Raise an error to simulate certain problems for unit tests.
    """
    raise exception_type


def _test_print(inference_state, stderr=None, stdout=None):
    """
    Force some prints in the subprocesses. This exists for unit tests.
    """
    if stderr is not None:
        print(stderr, file=sys.stderr)
        sys.stderr.flush()
    if stdout is not None:
        print(stdout)
        sys.stdout.flush()


def _get_init_path(directory_path):
    """
    The __init__ file can be searched in a directory. If found return it, else
    None.
    """
    for suffix in all_suffixes():
        path = os.path.join(directory_path, '__init__' + suffix)
        if os.path.exists(path):
            return path
    return None


def safe_literal_eval(inference_state, value):
    return parser_utils.safe_literal_eval(value)
