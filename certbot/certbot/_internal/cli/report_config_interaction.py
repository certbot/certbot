"""This is a module that reports config option interaction that should be
checked by set_by_cli"""
import six

from certbot._internal.cli import VAR_MODIFIERS


def report_config_interaction(modified, modifiers):
    """Registers config option interaction to be checked by set_by_cli.

    This function can be called by during the __init__ or
    add_parser_arguments methods of plugins to register interactions
    between config options.

    :param modified: config options that can be modified by modifiers
    :type modified: iterable or str (string_types)
    :param modifiers: config options that modify modified
    :type modifiers: iterable or str (string_types)

    """
    if isinstance(modified, six.string_types):
        modified = (modified,)
    if isinstance(modifiers, six.string_types):
        modifiers = (modifiers,)

    for var in modified:
        VAR_MODIFIERS.setdefault(var, set()).update(modifiers)
