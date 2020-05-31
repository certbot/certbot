"""
The API basically only provides one class. You can create a :class:`Script` and
use its methods.

Additionally you can add a debug function with :func:`set_debug_function`.
Alternatively, if you don't need a custom function and are happy with printing
debug messages to stdout, simply call :func:`set_debug_function` without
arguments.

.. warning:: Please, note that Jedi is **not thread safe**.
"""
import os
import sys
import warnings

import parso
from parso.python import tree

from jedi._compatibility import force_unicode, cast_path, is_py3
from jedi.parser_utils import get_executable_nodes
from jedi import debug
from jedi import settings
from jedi import cache
from jedi.file_io import KnownContentFileIO
from jedi.api import classes
from jedi.api import interpreter
from jedi.api import helpers
from jedi.api.helpers import validate_line_column
from jedi.api.completion import Completion
from jedi.api.keywords import KeywordName
from jedi.api.environment import InterpreterEnvironment
from jedi.api.project import get_default_project, Project
from jedi.inference import InferenceState
from jedi.inference import imports
from jedi.inference.references import find_references
from jedi.inference.arguments import try_iter_content
from jedi.inference.helpers import get_module_names, infer_call_of_leaf
from jedi.inference.sys_path import transform_path_to_dotted
from jedi.inference.syntax_tree import tree_name_to_values
from jedi.inference.value import ModuleValue
from jedi.inference.base_value import ValueSet
from jedi.inference.value.iterable import unpack_tuple_to_dict
from jedi.inference.gradual.conversion import convert_names, convert_values
from jedi.inference.gradual.utils import load_proper_stub_module

# Jedi uses lots and lots of recursion. By setting this a little bit higher, we
# can remove some "maximum recursion depth" errors.
sys.setrecursionlimit(3000)


class Script(object):
    """
    A Script is the base for completions, goto or whatever you want to do with
    |jedi|.

    You can either use the ``source`` parameter or ``path`` to read a file.
    Usually you're going to want to use both of them (in an editor).

    The script might be analyzed in a different ``sys.path`` than |jedi|:

    - if `sys_path` parameter is not ``None``, it will be used as ``sys.path``
      for the script;

    - if `sys_path` parameter is ``None`` and ``VIRTUAL_ENV`` environment
      variable is defined, ``sys.path`` for the specified environment will be
      guessed (see :func:`jedi.inference.sys_path.get_venv_path`) and used for
      the script;

    - otherwise ``sys.path`` will match that of |jedi|.

    :param source: The source code of the current file, separated by newlines.
    :type source: str
    :param line: Deprecated, please use it directly on e.g. `.complete`
    :type line: int
    :param column: Deprecated, please use it directly on e.g. `.complete`
    :type column: int
    :param path: The path of the file in the file system, or ``''`` if
        it hasn't been saved yet.
    :type path: str or None
    :param encoding: The encoding of ``source``, if it is not a
        ``unicode`` object (default ``'utf-8'``).
    :type encoding: str
    :param sys_path: ``sys.path`` to use during analysis of the script
    :type sys_path: list
    :param environment: TODO
    :type environment: Environment
    """
    def __init__(self, source=None, line=None, column=None, path=None,
                 encoding='utf-8', sys_path=None, environment=None,
                 _project=None):
        self._orig_path = path
        # An empty path (also empty string) should always result in no path.
        self.path = os.path.abspath(path) if path else None

        if source is None:
            # TODO add a better warning than the traceback!
            with open(path, 'rb') as f:
                source = f.read()

        # Load the Python grammar of the current interpreter.
        self._grammar = parso.load_grammar()

        if sys_path is not None and not is_py3:
            sys_path = list(map(force_unicode, sys_path))

        project = _project
        if project is None:
            # Load the Python grammar of the current interpreter.
            project = get_default_project(
                os.path.dirname(self.path)if path else os.getcwd()
            )
        # TODO deprecate and remove sys_path from the Script API.
        if sys_path is not None:
            project._sys_path = sys_path
        self._inference_state = InferenceState(
            project, environment=environment, script_path=self.path
        )
        debug.speed('init')
        self._module_node, source = self._inference_state.parse_and_get_code(
            code=source,
            path=self.path,
            encoding=encoding,
            use_latest_grammar=path and path.endswith('.pyi'),
            cache=False,  # No disk cache, because the current script often changes.
            diff_cache=settings.fast_parser,
            cache_path=settings.cache_directory,
        )
        debug.speed('parsed')
        self._code_lines = parso.split_lines(source, keepends=True)
        self._code = source
        self._pos = line, column

        cache.clear_time_caches()
        debug.reset_time()

    # Cache the module, this is mostly useful for testing, since this shouldn't
    # be called multiple times.
    @cache.memoize_method
    def _get_module(self):
        names = None
        is_package = False
        if self.path is not None:
            import_names, is_p = transform_path_to_dotted(
                self._inference_state.get_sys_path(add_parent_paths=False),
                self.path
            )
            if import_names is not None:
                names = import_names
                is_package = is_p

        if self.path is None:
            file_io = None
        else:
            file_io = KnownContentFileIO(cast_path(self.path), self._code)
        if self.path is not None and self.path.endswith('.pyi'):
            # We are in a stub file. Try to load the stub properly.
            stub_module = load_proper_stub_module(
                self._inference_state,
                file_io,
                names,
                self._module_node
            )
            if stub_module is not None:
                return stub_module

        if names is None:
            names = ('__main__',)

        module = ModuleValue(
            self._inference_state, self._module_node,
            file_io=file_io,
            string_names=names,
            code_lines=self._code_lines,
            is_package=is_package,
        )
        if names[0] not in ('builtins', '__builtin__', 'typing'):
            # These modules are essential for Jedi, so don't overwrite them.
            self._inference_state.module_cache.add(names, ValueSet([module]))
        return module

    def _get_module_context(self):
        return self._get_module().as_context()

    def __repr__(self):
        return '<%s: %s %r>' % (
            self.__class__.__name__,
            repr(self._orig_path),
            self._inference_state.environment,
        )

    @validate_line_column
    def complete(self, line=None, column=None, **kwargs):
        """
        Return :class:`classes.Completion` objects. Those objects contain
        information about the completions, more than just names.

        :param fuzzy: Default False. Will return fuzzy completions, which means
            that e.g. ``ooa`` will match ``foobar``.
        :return: Completion objects, sorted by name and ``__`` comes last.
        :rtype: list of :class:`classes.Completion`
        """
        return self._complete(line, column, **kwargs)

    def _complete(self, line, column, fuzzy=False):  # Python 2...
        with debug.increase_indent_cm('complete'):
            completion = Completion(
                self._inference_state, self._get_module_context(), self._code_lines,
                (line, column), self.get_signatures, fuzzy=fuzzy,
            )
            return completion.complete()

    def completions(self, fuzzy=False):
        # Deprecated, will be removed.
        return self.complete(*self._pos, fuzzy=fuzzy)

    @validate_line_column
    def infer(self, line=None, column=None, **kwargs):
        """
        Return the definitions of a the path under the cursor.  goto function!
        This follows complicated paths and returns the end, not the first
        definition. The big difference between :meth:`goto` and
        :meth:`infer` is that :meth:`goto` doesn't
        follow imports and statements. Multiple objects may be returned,
        because Python itself is a dynamic language, which means depending on
        an option you can have two different versions of a function.

        :param only_stubs: Only return stubs for this goto call.
        :param prefer_stubs: Prefer stubs to Python objects for this type
            inference call.
        :rtype: list of :class:`classes.Definition`
        """
        with debug.increase_indent_cm('infer'):
            return self._infer(line, column, **kwargs)

    def goto_definitions(self, **kwargs):
        # Deprecated, will be removed.
        return self.infer(*self._pos, **kwargs)

    def _infer(self, line, column, only_stubs=False, prefer_stubs=False):
        pos = line, column
        leaf = self._module_node.get_name_of_position(pos)
        if leaf is None:
            leaf = self._module_node.get_leaf_for_position(pos)
            if leaf is None or leaf.type == 'string':
                return []

        context = self._get_module_context().create_context(leaf)

        values = helpers.infer(self._inference_state, context, leaf)
        values = convert_values(
            values,
            only_stubs=only_stubs,
            prefer_stubs=prefer_stubs,
        )

        defs = [classes.Definition(self._inference_state, c.name) for c in values]
        # The additional set here allows the definitions to become unique in an
        # API sense. In the internals we want to separate more things than in
        # the API.
        return helpers.sorted_definitions(set(defs))

    def goto_assignments(self, follow_imports=False, follow_builtin_imports=False, **kwargs):
        # Deprecated, will be removed.
        return self.goto(*self._pos,
                         follow_imports=follow_imports,
                         follow_builtin_imports=follow_builtin_imports,
                         **kwargs)

    @validate_line_column
    def goto(self, line=None, column=None, **kwargs):
        """
        Return the first definition found, while optionally following imports.
        Multiple objects may be returned, because Python itself is a
        dynamic language, which means depending on an option you can have two
        different versions of a function.

        :param follow_imports: The goto call will follow imports.
        :param follow_builtin_imports: If follow_imports is True will decide if
            it follow builtin imports.
        :param only_stubs: Only return stubs for this goto call.
        :param prefer_stubs: Prefer stubs to Python objects for this goto call.
        :rtype: list of :class:`classes.Definition`
        """
        with debug.increase_indent_cm('goto'):
            return self._goto(line, column, **kwargs)

    def _goto(self, line, column, follow_imports=False, follow_builtin_imports=False,
              only_stubs=False, prefer_stubs=False):
        tree_name = self._module_node.get_name_of_position((line, column))
        if tree_name is None:
            # Without a name we really just want to jump to the result e.g.
            # executed by `foo()`, if we the cursor is after `)`.
            return self.infer(line, column, only_stubs=only_stubs, prefer_stubs=prefer_stubs)
        name = self._get_module_context().create_name(tree_name)

        # Make it possible to goto the super class function/attribute
        # definitions, when they are overwritten.
        names = []
        if name.tree_name.is_definition() and name.parent_context.is_class():
            class_node = name.parent_context.tree_node
            class_value = self._get_module_context().create_value(class_node)
            mro = class_value.py__mro__()
            next(mro)  # Ignore the first entry, because it's the class itself.
            for cls in mro:
                names = cls.goto(tree_name.value)
                if names:
                    break

        if not names:
            names = list(name.goto())

        if follow_imports:
            names = helpers.filter_follow_imports(names)
        names = convert_names(
            names,
            only_stubs=only_stubs,
            prefer_stubs=prefer_stubs,
        )

        defs = [classes.Definition(self._inference_state, d) for d in set(names)]
        return helpers.sorted_definitions(defs)

    @validate_line_column
    def help(self, line=None, column=None):
        """
        Works like goto and returns a list of Definition objects. Returns
        additional definitions for keywords and operators.

        The additional definitions are of ``Definition(...).type == 'keyword'``.
        These definitions do not have a lot of value apart from their docstring
        attribute, which contains the output of Python's ``help()`` function.

        :rtype: list of :class:`classes.Definition`
        """
        definitions = self.goto(line, column, follow_imports=True)
        if definitions:
            return definitions
        leaf = self._module_node.get_leaf_for_position((line, column))
        if leaf.type in ('keyword', 'operator', 'error_leaf'):
            reserved = self._grammar._pgen_grammar.reserved_syntax_strings.keys()
            if leaf.value in reserved:
                name = KeywordName(self._inference_state, leaf.value)
                return [classes.Definition(self._inference_state, name)]
        return []

    def usages(self, **kwargs):
        # Deprecated, will be removed.
        return self.get_references(*self._pos, **kwargs)

    @validate_line_column
    def get_references(self, line=None, column=None, **kwargs):
        """
        Return :class:`classes.Definition` objects, which contain all
        names that point to the definition of the name under the cursor. This
        is very useful for refactoring (renaming), or to show all references of
        a variable.

        :param include_builtins: Default True, checks if a reference is a
            builtin (e.g. ``sys``) and in that case does not return it.
        :rtype: list of :class:`classes.Definition`
        """

        def _references(include_builtins=True):
            tree_name = self._module_node.get_name_of_position((line, column))
            if tree_name is None:
                # Must be syntax
                return []

            names = find_references(self._get_module_context(), tree_name)

            definitions = [classes.Definition(self._inference_state, n) for n in names]
            if not include_builtins:
                definitions = [d for d in definitions if not d.in_builtin_module()]
            return helpers.sorted_definitions(definitions)
        return _references(**kwargs)

    def call_signatures(self):
        # Deprecated, will be removed.
        return self.get_signatures(*self._pos)

    @validate_line_column
    def get_signatures(self, line=None, column=None):
        """
        Return the function object of the call you're currently in.

        E.g. if the cursor is here::

            abs(# <-- cursor is here

        This would return the ``abs`` function. On the other hand::

            abs()# <-- cursor is here

        This would return an empty list..

        :rtype: list of :class:`classes.Signature`
        """
        pos = line, column
        call_details = helpers.get_signature_details(self._module_node, pos)
        if call_details is None:
            return []

        context = self._get_module_context().create_context(call_details.bracket_leaf)
        definitions = helpers.cache_signatures(
            self._inference_state,
            context,
            call_details.bracket_leaf,
            self._code_lines,
            pos
        )
        debug.speed('func_call followed')

        # TODO here we use stubs instead of the actual values. We should use
        # the signatures from stubs, but the actual values, probably?!
        return [classes.Signature(self._inference_state, signature, call_details)
                for signature in definitions.get_signatures()]

    @validate_line_column
    def get_context(self, line=None, column=None):
        pos = (line, column)
        leaf = self._module_node.get_leaf_for_position(pos, include_prefixes=True)
        if leaf.start_pos > pos or leaf.type == 'endmarker':
            previous_leaf = leaf.get_previous_leaf()
            if previous_leaf is not None:
                leaf = previous_leaf

        module_context = self._get_module_context()

        n = tree.search_ancestor(leaf, 'funcdef', 'classdef')
        if n is not None and n.start_pos < pos <= n.children[-1].start_pos:
            # This is a bit of a special case. The context of a function/class
            # name/param/keyword is always it's parent context, not the
            # function itself. Catch all the cases here where we are before the
            # suite object, but still in the function.
            context = module_context.create_value(n).as_context()
        else:
            context = module_context.create_context(leaf)

        while context.name is None:
            context = context.parent_context  # comprehensions

        definition = classes.Definition(self._inference_state, context.name)
        while definition.type != 'module':
            name = definition._name  # TODO private access
            tree_name = name.tree_name
            if tree_name is not None:  # Happens with lambdas.
                scope = tree_name.get_definition()
                if scope.start_pos[1] < column:
                    break
            definition = definition.parent()
        return definition

    def _analysis(self):
        self._inference_state.is_analysis = True
        self._inference_state.analysis_modules = [self._module_node]
        module = self._get_module_context()
        try:
            for node in get_executable_nodes(self._module_node):
                context = module.create_context(node)
                if node.type in ('funcdef', 'classdef'):
                    # Resolve the decorators.
                    tree_name_to_values(self._inference_state, context, node.children[1])
                elif isinstance(node, tree.Import):
                    import_names = set(node.get_defined_names())
                    if node.is_nested():
                        import_names |= set(path[-1] for path in node.get_paths())
                    for n in import_names:
                        imports.infer_import(context, n)
                elif node.type == 'expr_stmt':
                    types = context.infer_node(node)
                    for testlist in node.children[:-1:2]:
                        # Iterate tuples.
                        unpack_tuple_to_dict(context, types, testlist)
                else:
                    if node.type == 'name':
                        defs = self._inference_state.infer(context, node)
                    else:
                        defs = infer_call_of_leaf(context, node)
                    try_iter_content(defs)
                self._inference_state.reset_recursion_limitations()

            ana = [a for a in self._inference_state.analysis if self.path == a.path]
            return sorted(set(ana), key=lambda x: x.line)
        finally:
            self._inference_state.is_analysis = False

    def get_names(self, **kwargs):
        """
        Returns a list of `Definition` objects, containing name parts.
        This means you can call ``Definition.goto()`` and get the
        reference of a name.

        :param all_scopes: If True lists the names of all scopes instead of only
            the module namespace.
        :param definitions: If True lists the names that have been defined by a
            class, function or a statement (``a = b`` returns ``a``).
        :param references: If True lists all the names that are not listed by
            ``definitions=True``. E.g. ``a = b`` returns ``b``.
        """
        return self._names(**kwargs)  # Python 2...

    def _names(self, all_scopes=False, definitions=True, references=False):
        def def_ref_filter(_def):
            is_def = _def._name.tree_name.is_definition()
            return definitions and is_def or references and not is_def

        # Set line/column to a random position, because they don't matter.
        module_context = self._get_module_context()
        defs = [
            classes.Definition(
                self._inference_state,
                module_context.create_name(name)
            ) for name in get_module_names(self._module_node, all_scopes)
        ]
        return sorted(filter(def_ref_filter, defs), key=lambda x: (x.line, x.column))


class Interpreter(Script):
    """
    Jedi API for Python REPLs.

    In addition to completion of simple attribute access, Jedi
    supports code completion based on static code analysis.
    Jedi can complete attributes of object which is not initialized
    yet.

    >>> from os.path import join
    >>> namespace = locals()
    >>> script = Interpreter('join("").up', [namespace])
    >>> print(script.complete()[0].name)
    upper
    """
    _allow_descriptor_getattr_default = True

    def __init__(self, source, namespaces, **kwds):
        """
        Parse `source` and mixin interpreted Python objects from `namespaces`.

        :type source: str
        :arg  source: Code to parse.
        :type namespaces: list of dict
        :arg  namespaces: a list of namespace dictionaries such as the one
                          returned by :func:`locals`.

        Other optional arguments are same as the ones for :class:`Script`.
        If `line` and `column` are None, they are assumed be at the end of
        `source`.
        """
        try:
            namespaces = [dict(n) for n in namespaces]
        except Exception:
            raise TypeError("namespaces must be a non-empty list of dicts.")

        environment = kwds.get('environment', None)
        if environment is None:
            environment = InterpreterEnvironment()
        else:
            if not isinstance(environment, InterpreterEnvironment):
                raise TypeError("The environment needs to be an InterpreterEnvironment subclass.")

        super(Interpreter, self).__init__(source, environment=environment,
                                          _project=Project(os.getcwd()), **kwds)
        self.namespaces = namespaces
        self._inference_state.allow_descriptor_getattr = self._allow_descriptor_getattr_default

    @cache.memoize_method
    def _get_module_context(self):
        tree_module_value = ModuleValue(
            self._inference_state, self._module_node,
            file_io=KnownContentFileIO(self.path, self._code),
            string_names=('__main__',),
            code_lines=self._code_lines,
        )
        return interpreter.MixedModuleContext(
            tree_module_value,
            self.namespaces,
        )


def names(source=None, path=None, encoding='utf-8', all_scopes=False,
          definitions=True, references=False, environment=None):
    warnings.warn(
        "Deprecated since version 0.16.0. Use Script(...).get_names instead.",
        DeprecationWarning,
        stacklevel=2
    )

    return Script(source, path=path, encoding=encoding).get_names(
        all_scopes=all_scopes,
        definitions=definitions,
        references=references,
    )


def preload_module(*modules):
    """
    Preloading modules tells Jedi to load a module now, instead of lazy parsing
    of modules. Usful for IDEs, to control which modules to load on startup.

    :param modules: different module names, list of string.
    """
    for m in modules:
        s = "import %s as x; x." % m
        Script(s, path=None).complete(1, len(s))


def set_debug_function(func_cb=debug.print_to_stdout, warnings=True,
                       notices=True, speed=True):
    """
    Define a callback debug function to get all the debug messages.

    If you don't specify any arguments, debug messages will be printed to stdout.

    :param func_cb: The callback function for debug messages, with n params.
    """
    debug.debug_function = func_cb
    debug.enable_warning = warnings
    debug.enable_notice = notices
    debug.enable_speed = speed
