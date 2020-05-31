import copy
import sys
import re
import os
from itertools import chain
from contextlib import contextmanager

from parso.python import tree

from jedi._compatibility import unicode
from jedi.parser_utils import get_parent_scope


def is_stdlib_path(path):
    # Python standard library paths look like this:
    # /usr/lib/python3.5/...
    # TODO The implementation below is probably incorrect and not complete.
    if 'dist-packages' in path or 'site-packages' in path:
        return False

    base_path = os.path.join(sys.prefix, 'lib', 'python')
    return bool(re.match(re.escape(base_path) + r'\d.\d', path))


def deep_ast_copy(obj):
    """
    Much, much faster than copy.deepcopy, but just for parser tree nodes.
    """
    # If it's already in the cache, just return it.
    new_obj = copy.copy(obj)

    # Copy children
    new_children = []
    for child in obj.children:
        if isinstance(child, tree.Leaf):
            new_child = copy.copy(child)
            new_child.parent = new_obj
        else:
            new_child = deep_ast_copy(child)
            new_child.parent = new_obj
        new_children.append(new_child)
    new_obj.children = new_children

    return new_obj


def infer_call_of_leaf(context, leaf, cut_own_trailer=False):
    """
    Creates a "call" node that consist of all ``trailer`` and ``power``
    objects.  E.g. if you call it with ``append``::

        list([]).append(3) or None

    You would get a node with the content ``list([]).append`` back.

    This generates a copy of the original ast node.

    If you're using the leaf, e.g. the bracket `)` it will return ``list([])``.

    We use this function for two purposes. Given an expression ``bar.foo``,
    we may want to
      - infer the type of ``foo`` to offer completions after foo
      - infer the type of ``bar`` to be able to jump to the definition of foo
    The option ``cut_own_trailer`` must be set to true for the second purpose.
    """
    trailer = leaf.parent
    if trailer.type == 'fstring':
        from jedi.inference import compiled
        return compiled.get_string_value_set(context.inference_state)

    # The leaf may not be the last or first child, because there exist three
    # different trailers: `( x )`, `[ x ]` and `.x`. In the first two examples
    # we should not match anything more than x.
    if trailer.type != 'trailer' or leaf not in (trailer.children[0], trailer.children[-1]):
        if leaf == ':':
            # Basically happens with foo[:] when the cursor is on the colon
            from jedi.inference.base_value import NO_VALUES
            return NO_VALUES
        if trailer.type == 'atom':
            return context.infer_node(trailer)
        return context.infer_node(leaf)

    power = trailer.parent
    index = power.children.index(trailer)
    if cut_own_trailer:
        cut = index
    else:
        cut = index + 1

    if power.type == 'error_node':
        start = index
        while True:
            start -= 1
            base = power.children[start]
            if base.type != 'trailer':
                break
        trailers = power.children[start + 1:cut]
    else:
        base = power.children[0]
        trailers = power.children[1:cut]

    if base == 'await':
        base = trailers[0]
        trailers = trailers[1:]

    values = context.infer_node(base)
    from jedi.inference.syntax_tree import infer_trailer
    for trailer in trailers:
        values = infer_trailer(context, values, trailer)
    return values


def get_names_of_node(node):
    try:
        children = node.children
    except AttributeError:
        if node.type == 'name':
            return [node]
        else:
            return []
    else:
        return list(chain.from_iterable(get_names_of_node(c) for c in children))


def get_module_names(module, all_scopes):
    """
    Returns a dictionary with name parts as keys and their call paths as
    values.
    """
    names = list(chain.from_iterable(module.get_used_names().values()))
    if not all_scopes:
        # We have to filter all the names that don't have the module as a
        # parent_scope. There's None as a parent, because nodes in the module
        # node have the parent module and not suite as all the others.
        # Therefore it's important to catch that case.

        def is_module_scope_name(name):
            parent_scope = get_parent_scope(name)
            # async functions have an extra wrapper. Strip it.
            if parent_scope and parent_scope.type == 'async_stmt':
                parent_scope = parent_scope.parent
            return parent_scope in (module, None)

        names = [n for n in names if is_module_scope_name(n)]
    return names


def is_string(value):
    if value.inference_state.environment.version_info.major == 2:
        str_classes = (unicode, bytes)
    else:
        str_classes = (unicode,)
    return value.is_compiled() and isinstance(value.get_safe_value(default=None), str_classes)


def is_literal(value):
    return is_number(value) or is_string(value)


def _get_safe_value_or_none(value, accept):
    value = value.get_safe_value(default=None)
    if isinstance(value, accept):
        return value


def get_int_or_none(value):
    return _get_safe_value_or_none(value, int)


def get_str_or_none(value):
    return _get_safe_value_or_none(value, (bytes, unicode))


def is_number(value):
    return _get_safe_value_or_none(value, (int, float)) is not None


class SimpleGetItemNotFound(Exception):
    pass


@contextmanager
def reraise_getitem_errors(*exception_classes):
    try:
        yield
    except exception_classes as e:
        raise SimpleGetItemNotFound(e)


def parse_dotted_names(nodes, is_import_from, until_node=None):
    level = 0
    names = []
    for node in nodes[1:]:
        if node in ('.', '...'):
            if not names:
                level += len(node.value)
        elif node.type == 'dotted_name':
            for n in node.children[::2]:
                names.append(n)
                if n is until_node:
                    break
            else:
                continue
            break
        elif node.type == 'name':
            names.append(node)
            if node is until_node:
                break
        elif node == ',':
            if not is_import_from:
                names = []
        else:
            # Here if the keyword `import` comes along it stops checking
            # for names.
            break
    return level, names


def values_from_qualified_names(inference_state, *names):
    return inference_state.import_module(names[:-1]).py__getattribute__(names[-1])


def is_big_annoying_library(context):
    string_names = context.get_root_context().string_names
    if string_names is None:
        return False

    # Especially pandas and tensorflow are huge complicated Python libraries
    # that get even slower than they already are when Jedi tries to undrstand
    # dynamic features like decorators, ifs and other stuff.
    return string_names[0] in ('pandas', 'numpy', 'tensorflow', 'matplotlib')
