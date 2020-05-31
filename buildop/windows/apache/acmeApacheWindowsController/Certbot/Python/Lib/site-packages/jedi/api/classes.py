"""
The :mod:`jedi.api.classes` module contains the return classes of the API.
These classes are the much bigger part of the whole API, because they contain
the interesting information about completion and goto operations.
"""
import re
import sys
import warnings

from parso.python.tree import search_ancestor

from jedi import settings
from jedi import debug
from jedi.inference.utils import unite
from jedi.cache import memoize_method
from jedi.inference import imports
from jedi.inference.imports import ImportName
from jedi.inference.gradual.typeshed import StubModuleValue
from jedi.inference.gradual.conversion import convert_names, convert_values
from jedi.inference.base_value import ValueSet
from jedi.api.keywords import KeywordName
from jedi.api import completion_cache
from jedi.api.helpers import filter_follow_imports


def _sort_names_by_start_pos(names):
    return sorted(names, key=lambda s: s.start_pos or (0, 0))


def defined_names(inference_state, context):
    """
    List sub-definitions (e.g., methods in class).

    :type scope: Scope
    :rtype: list of Definition
    """
    filter = next(context.get_filters())
    names = [name for name in filter.values()]
    return [Definition(inference_state, n) for n in _sort_names_by_start_pos(names)]


def _values_to_definitions(values):
    return [Definition(c.inference_state, c.name) for c in values]


class BaseDefinition(object):
    _mapping = {
        'posixpath': 'os.path',
        'riscospath': 'os.path',
        'ntpath': 'os.path',
        'os2emxpath': 'os.path',
        'macpath': 'os.path',
        'genericpath': 'os.path',
        'posix': 'os',
        '_io': 'io',
        '_functools': 'functools',
        '_collections': 'collections',
        '_socket': 'socket',
        '_sqlite3': 'sqlite3',
        '__builtin__': 'builtins',
    }

    _tuple_mapping = dict((tuple(k.split('.')), v) for (k, v) in {
        'argparse._ActionsContainer': 'argparse.ArgumentParser',
    }.items())

    def __init__(self, inference_state, name):
        self._inference_state = inference_state
        self._name = name
        """
        An instance of :class:`parso.python.tree.Name` subclass.
        """
        self.is_keyword = isinstance(self._name, KeywordName)

    @memoize_method
    def _get_module_context(self):
        # This can take a while to complete, because in the worst case of
        # imports (consider `import a` completions), we need to load all
        # modules starting with a first.
        return self._name.get_root_context()

    @property
    def module_path(self):
        """Shows the file path of a module. e.g. ``/usr/lib/python2.7/os.py``"""
        module = self._get_module_context()
        if module.is_stub() or not module.is_compiled():
            # Compiled modules should not return a module path even if they
            # have one.
            return self._get_module_context().py__file__()

        return None

    @property
    def name(self):
        """
        Name of variable/function/class/module.

        For example, for ``x = None`` it returns ``'x'``.

        :rtype: str or None
        """
        return self._name.get_public_name()

    @property
    def type(self):
        """
        The type of the definition.

        Here is an example of the value of this attribute.  Let's consider
        the following source.  As what is in ``variable`` is unambiguous
        to Jedi, :meth:`jedi.Script.infer` should return a list of
        definition for ``sys``, ``f``, ``C`` and ``x``.

        >>> from jedi._compatibility import no_unicode_pprint
        >>> from jedi import Script
        >>> source = '''
        ... import keyword
        ...
        ... class C:
        ...     pass
        ...
        ... class D:
        ...     pass
        ...
        ... x = D()
        ...
        ... def f():
        ...     pass
        ...
        ... for variable in [keyword, f, C, x]:
        ...     variable'''

        >>> script = Script(source)
        >>> defs = script.infer()

        Before showing what is in ``defs``, let's sort it by :attr:`line`
        so that it is easy to relate the result to the source code.

        >>> defs = sorted(defs, key=lambda d: d.line)
        >>> no_unicode_pprint(defs)  # doctest: +NORMALIZE_WHITESPACE
        [<Definition full_name='keyword', description='module keyword'>,
         <Definition full_name='__main__.C', description='class C'>,
         <Definition full_name='__main__.D', description='instance D'>,
         <Definition full_name='__main__.f', description='def f'>]

        Finally, here is what you can get from :attr:`type`:

        >>> defs = [str(d.type) for d in defs]  # It's unicode and in Py2 has u before it.
        >>> defs[0]
        'module'
        >>> defs[1]
        'class'
        >>> defs[2]
        'instance'
        >>> defs[3]
        'function'

        Valid values for are ``module``, ``class``, ``instance``, ``function``,
        ``param``, ``path`` and ``keyword``.

        """
        tree_name = self._name.tree_name
        resolve = False
        if tree_name is not None:
            # TODO move this to their respective names.
            definition = tree_name.get_definition()
            if definition is not None and definition.type == 'import_from' and \
                    tree_name.is_definition():
                resolve = True

        if isinstance(self._name, imports.SubModuleName) or resolve:
            for value in self._name.infer():
                return value.api_type
        return self._name.api_type

    @property
    def module_name(self):
        """
        The module name.

        >>> from jedi import Script
        >>> source = 'import json'
        >>> script = Script(source, path='example.py')
        >>> d = script.infer()[0]
        >>> print(d.module_name)  # doctest: +ELLIPSIS
        json
        """
        return self._get_module_context().py__name__()

    def in_builtin_module(self):
        """Whether this is a builtin module."""
        value = self._get_module_context().get_value()
        if isinstance(value, StubModuleValue):
            return any(v.is_compiled() for v in value.non_stub_value_set)
        return value.is_compiled()

    @property
    def line(self):
        """The line where the definition occurs (starting with 1)."""
        start_pos = self._name.start_pos
        if start_pos is None:
            return None
        return start_pos[0]

    @property
    def column(self):
        """The column where the definition occurs (starting with 0)."""
        start_pos = self._name.start_pos
        if start_pos is None:
            return None
        return start_pos[1]

    def docstring(self, raw=False, fast=True):
        r"""
        Return a document string for this completion object.

        Example:

        >>> from jedi import Script
        >>> source = '''\
        ... def f(a, b=1):
        ...     "Document for function f."
        ... '''
        >>> script = Script(source, path='example.py')
        >>> doc = script.infer(1, len('def f'))[0].docstring()
        >>> print(doc)
        f(a, b=1)
        <BLANKLINE>
        Document for function f.

        Notice that useful extra information is added to the actual
        docstring.  For function, it is signature.  If you need
        actual docstring, use ``raw=True`` instead.

        >>> print(script.infer(1, len('def f'))[0].docstring(raw=True))
        Document for function f.

        :param fast: Don't follow imports that are only one level deep like
            ``import foo``, but follow ``from foo import bar``. This makes
            sense for speed reasons. Completing `import a` is slow if you use
            the ``foo.docstring(fast=False)`` on every object, because it
            parses all libraries starting with ``a``.
        """
        if isinstance(self._name, ImportName) and fast:
            return ''
        doc = self._get_docstring()
        if raw:
            return doc

        signature_text = self._get_docstring_signature()
        if signature_text and doc:
            return signature_text + '\n\n' + doc
        else:
            return signature_text + doc

    def _get_docstring(self):
        return self._name.py__doc__()

    def _get_docstring_signature(self):
        return '\n'.join(
            signature.to_string()
            for signature in self._get_signatures(for_docstring=True)
        )

    @property
    def description(self):
        """
        A description of the :class:`.Definition` object, which is heavily used
        in testing. e.g. for ``isinstance`` it returns ``def isinstance``.

        Example:

        >>> from jedi._compatibility import no_unicode_pprint
        >>> from jedi import Script
        >>> source = '''
        ... def f():
        ...     pass
        ...
        ... class C:
        ...     pass
        ...
        ... variable = f if random.choice([0,1]) else C'''
        >>> script = Script(source)  # line is maximum by default
        >>> defs = script.infer(column=3)
        >>> defs = sorted(defs, key=lambda d: d.line)
        >>> no_unicode_pprint(defs)  # doctest: +NORMALIZE_WHITESPACE
        [<Definition full_name='__main__.f', description='def f'>,
         <Definition full_name='__main__.C', description='class C'>]
        >>> str(defs[0].description)  # strip literals in python2
        'def f'
        >>> str(defs[1].description)
        'class C'

        """
        typ = self.type
        tree_name = self._name.tree_name
        if typ == 'param':
            return typ + ' ' + self._name.to_string()
        if typ in ('function', 'class', 'module', 'instance') or tree_name is None:
            if typ == 'function':
                # For the description we want a short and a pythonic way.
                typ = 'def'
            return typ + ' ' + self._name.get_public_name()

        definition = tree_name.get_definition(include_setitem=True) or tree_name
        # Remove the prefix, because that's not what we want for get_code
        # here.
        txt = definition.get_code(include_prefix=False)
        # Delete comments:
        txt = re.sub(r'#[^\n]+\n', ' ', txt)
        # Delete multi spaces/newlines
        txt = re.sub(r'\s+', ' ', txt).strip()
        return txt

    @property
    def full_name(self):
        """
        Dot-separated path of this object.

        It is in the form of ``<module>[.<submodule>[...]][.<object>]``.
        It is useful when you want to look up Python manual of the
        object at hand.

        Example:

        >>> from jedi import Script
        >>> source = '''
        ... import os
        ... os.path.join'''
        >>> script = Script(source, path='example.py')
        >>> print(script.infer(3, len('os.path.join'))[0].full_name)
        os.path.join

        Notice that it returns ``'os.path.join'`` instead of (for example)
        ``'posixpath.join'``. This is not correct, since the modules name would
        be ``<module 'posixpath' ...>```. However most users find the latter
        more practical.
        """
        if not self._name.is_value_name:
            return None

        names = self._name.get_qualified_names(include_module_names=True)
        if names is None:
            return names

        names = list(names)
        try:
            names[0] = self._mapping[names[0]]
        except KeyError:
            pass

        return '.'.join(names)

    def is_stub(self):
        if not self._name.is_value_name:
            return False

        return self._name.get_root_context().is_stub()

    def goto(self, **kwargs):
        with debug.increase_indent_cm('goto for %s' % self._name):
            return self._goto(**kwargs)

    def goto_assignments(self, **kwargs):  # Python 2...
        warnings.warn(
            "Deprecated since version 0.16.0. Use .goto.",
            DeprecationWarning,
            stacklevel=2
        )
        return self.goto(**kwargs)

    def _goto(self, follow_imports=False, follow_builtin_imports=False,
              only_stubs=False, prefer_stubs=False):

        if not self._name.is_value_name:
            return []

        names = self._name.goto()
        if follow_imports:
            names = filter_follow_imports(names, follow_builtin_imports)
        names = convert_names(
            names,
            only_stubs=only_stubs,
            prefer_stubs=prefer_stubs,
        )
        return [self if n == self._name else Definition(self._inference_state, n)
                for n in names]

    def infer(self, **kwargs):  # Python 2...
        with debug.increase_indent_cm('infer for %s' % self._name):
            return self._infer(**kwargs)

    def _infer(self, only_stubs=False, prefer_stubs=False):
        assert not (only_stubs and prefer_stubs)

        if not self._name.is_value_name:
            return []

        # First we need to make sure that we have stub names (if possible) that
        # we can follow. If we don't do that, we can end up with the inferred
        # results of Python objects instead of stubs.
        names = convert_names([self._name], prefer_stubs=True)
        values = convert_values(
            ValueSet.from_sets(n.infer() for n in names),
            only_stubs=only_stubs,
            prefer_stubs=prefer_stubs,
        )
        resulting_names = [c.name for c in values]
        return [self if n == self._name else Definition(self._inference_state, n)
                for n in resulting_names]

    @property
    @memoize_method
    def params(self):
        """
        Deprecated! Will raise a warning soon. Use get_signatures()[...].params.

        Raises an ``AttributeError`` if the definition is not callable.
        Otherwise returns a list of `Definition` that represents the params.
        """
        warnings.warn(
            "Deprecated since version 0.16.0. Use get_signatures()[...].params",
            DeprecationWarning,
            stacklevel=2
        )
        # Only return the first one. There might be multiple one, especially
        # with overloading.
        for signature in self._get_signatures():
            return [
                Definition(self._inference_state, n)
                for n in signature.get_param_names(resolve_stars=True)
            ]

        if self.type == 'function' or self.type == 'class':
            # Fallback, if no signatures were defined (which is probably by
            # itself a bug).
            return []
        raise AttributeError('There are no params defined on this.')

    def parent(self):
        if not self._name.is_value_name:
            return None

        if self.type in ('function', 'class', 'param') and self._name.tree_name is not None:
            # Since the parent_context doesn't really match what the user
            # thinks of that the parent is here, we do these cases separately.
            # The reason for this is the following:
            # - class: Nested classes parent_context is always the
            #   parent_context of the most outer one.
            # - function: Functions in classes have the module as
            #   parent_context.
            # - param: The parent_context of a param is not its function but
            #   e.g. the outer class or module.
            cls_or_func_node = self._name.tree_name.get_definition()
            parent = search_ancestor(cls_or_func_node, 'funcdef', 'classdef', 'file_input')
            context = self._get_module_context().create_value(parent).as_context()
        else:
            context = self._name.parent_context

        if context is None:
            return None
        while context.name is None:
            # Happens for comprehension contexts
            context = context.parent_context

        return Definition(self._inference_state, context.name)

    def __repr__(self):
        return "<%s %sname=%r, description=%r>" % (
            self.__class__.__name__,
            'full_' if self.full_name else '',
            self.full_name or self.name,
            self.description,
        )

    def get_line_code(self, before=0, after=0):
        """
        Returns the line of code where this object was defined.

        :param before: Add n lines before the current line to the output.
        :param after: Add n lines after the current line to the output.

        :return str: Returns the line(s) of code or an empty string if it's a
                     builtin.
        """
        if not self._name.is_value_name:
            return ''

        lines = self._name.get_root_context().code_lines
        if lines is None:
            # Probably a builtin module, just ignore in that case.
            return ''

        index = self._name.start_pos[0] - 1
        start_index = max(index - before, 0)
        return ''.join(lines[start_index:index + after + 1])

    def _get_signatures(self, for_docstring=False):
        if for_docstring and self._name.api_type == 'statement' and not self.is_stub():
            # For docstrings we don't resolve signatures if they are simple
            # statements and not stubs. This is a speed optimization.
            return []

        names = convert_names([self._name], prefer_stubs=True)
        return [sig for name in names for sig in name.infer().get_signatures()]

    def get_signatures(self):
        return [
            BaseSignature(self._inference_state, s)
            for s in self._get_signatures()
        ]

    def execute(self):
        return _values_to_definitions(self._name.infer().execute_with_values())


class Completion(BaseDefinition):
    """
    `Completion` objects are returned from :meth:`api.Script.complete`. They
    provide additional information about a completion.
    """
    def __init__(self, inference_state, name, stack, like_name_length,
                 is_fuzzy, cached_name=None):
        super(Completion, self).__init__(inference_state, name)

        self._like_name_length = like_name_length
        self._stack = stack
        self._is_fuzzy = is_fuzzy
        self._cached_name = cached_name

        # Completion objects with the same Completion name (which means
        # duplicate items in the completion)
        self._same_name_completions = []

    def _complete(self, like_name):
        append = ''
        if settings.add_bracket_after_function \
                and self.type == 'function':
            append = '('

        name = self._name.get_public_name()
        if like_name:
            name = name[self._like_name_length:]
        return name + append

    @property
    def complete(self):
        """
        Only works with non-fuzzy completions. Returns None if fuzzy
        completions are used.

        Return the rest of the word, e.g. completing ``isinstance``::

            isinstan# <-- Cursor is here

        would return the string 'ce'. It also adds additional stuff, depending
        on your `settings.py`.

        Assuming the following function definition::

            def foo(param=0):
                pass

        completing ``foo(par`` would give a ``Completion`` which `complete`
        would be `am=`
        """
        if self._is_fuzzy:
            return None
        return self._complete(True)

    @property
    def name_with_symbols(self):
        """
        Similar to :attr:`name`, but like :attr:`name` returns also the
        symbols, for example assuming the following function definition::

            def foo(param=0):
                pass

        completing ``foo(`` would give a ``Completion`` which
        ``name_with_symbols`` would be "param=".

        """
        return self._complete(False)

    def docstring(self, raw=False, fast=True):
        if self._like_name_length >= 3:
            # In this case we can just resolve the like name, because we
            # wouldn't load like > 100 Python modules anymore.
            fast = False

        return super(Completion, self).docstring(raw=raw, fast=fast)

    def _get_docstring(self):
        if self._cached_name is not None:
            return completion_cache.get_docstring(
                self._cached_name,
                self._name.get_public_name(),
                lambda: self._get_cache()
            )
        return super(Completion, self)._get_docstring()

    def _get_docstring_signature(self):
        if self._cached_name is not None:
            return completion_cache.get_docstring_signature(
                self._cached_name,
                self._name.get_public_name(),
                lambda: self._get_cache()
            )
        return super(Completion, self)._get_docstring_signature()

    def _get_cache(self):
        typ = super(Completion, self).type
        return (
            typ,
            super(Completion, self)._get_docstring_signature(),
            super(Completion, self)._get_docstring(),
        )

    @property
    def type(self):
        # Purely a speed optimization.
        if self._cached_name is not None:
            return completion_cache.get_type(
                self._cached_name,
                self._name.get_public_name(),
                lambda: self._get_cache()
            )

        return super(Completion, self).type

    def __repr__(self):
        return '<%s: %s>' % (type(self).__name__, self._name.get_public_name())

    @memoize_method
    def follow_definition(self):
        """
        Deprecated!

        Return the original definitions. I strongly recommend not using it for
        your completions, because it might slow down |jedi|. If you want to
        read only a few objects (<=20), it might be useful, especially to get
        the original docstrings. The basic problem of this function is that it
        follows all results. This means with 1000 completions (e.g.  numpy),
        it's just PITA-slow.
        """
        warnings.warn(
            "Deprecated since version 0.14.0. Use .infer.",
            DeprecationWarning,
            stacklevel=2
        )
        return self.infer()


class Definition(BaseDefinition):
    """
    *Definition* objects are returned from :meth:`api.Script.goto`
    or :meth:`api.Script.infer`.
    """
    def __init__(self, inference_state, definition):
        super(Definition, self).__init__(inference_state, definition)

    @property
    def desc_with_module(self):
        """
        In addition to the definition, also return the module.

        .. warning:: Don't use this function yet, its behaviour may change. If
            you really need it, talk to me.

        .. todo:: Add full path. This function is should return a
            `module.class.function` path.
        """
        position = '' if self.in_builtin_module else '@%s' % self.line
        return "%s:%s%s" % (self.module_name, self.description, position)

    @memoize_method
    def defined_names(self):
        """
        List sub-definitions (e.g., methods in class).

        :rtype: list of Definition
        """
        defs = self._name.infer()
        return sorted(
            unite(defined_names(self._inference_state, d.as_context()) for d in defs),
            key=lambda s: s._name.start_pos or (0, 0)
        )

    def is_definition(self):
        """
        Returns True, if defined as a name in a statement, function or class.
        Returns False, if it's a reference to such a definition.
        """
        if self._name.tree_name is None:
            return True
        else:
            return self._name.tree_name.is_definition()

    def __eq__(self, other):
        return self._name.start_pos == other._name.start_pos \
            and self.module_path == other.module_path \
            and self.name == other.name \
            and self._inference_state == other._inference_state

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self._name.start_pos, self.module_path, self.name, self._inference_state))


class BaseSignature(Definition):
    """
    `BaseSignature` objects is the return value of `Script.function_definition`.
    It knows what functions you are currently in. e.g. `isinstance(` would
    return the `isinstance` function. without `(` it would return nothing.
    """
    def __init__(self, inference_state, signature):
        super(BaseSignature, self).__init__(inference_state, signature.name)
        self._signature = signature

    @property
    def params(self):
        """
        :return list of ParamDefinition:
        """
        return [ParamDefinition(self._inference_state, n)
                for n in self._signature.get_param_names(resolve_stars=True)]

    def to_string(self):
        return self._signature.to_string()


class Signature(BaseSignature):
    """
    `Signature` objects is the return value of `Script.get_signatures`.
    It knows what functions you are currently in. e.g. `isinstance(` would
    return the `isinstance` function with its params. Without `(` it would
    return nothing.
    """
    def __init__(self, inference_state, signature, call_details):
        super(Signature, self).__init__(inference_state, signature)
        self._call_details = call_details
        self._signature = signature

    @property
    def index(self):
        """
        The Param index of the current call.
        Returns None if the index cannot be found in the curent call.
        """
        return self._call_details.calculate_index(
            self._signature.get_param_names(resolve_stars=True)
        )

    @property
    def bracket_start(self):
        """
        The line/column of the bracket that is responsible for the last
        function call.
        """
        return self._call_details.bracket_leaf.start_pos

    def __repr__(self):
        return '<%s: index=%r %s>' % (
            type(self).__name__,
            self.index,
            self._signature.to_string(),
        )


class ParamDefinition(Definition):
    def infer_default(self):
        """
        :return list of Definition:
        """
        return _values_to_definitions(self._name.infer_default())

    def infer_annotation(self, **kwargs):
        """
        :return list of Definition:

        :param execute_annotation: If False, the values are not executed and
            you get classes instead of instances.
        """
        return _values_to_definitions(self._name.infer_annotation(ignore_stars=True, **kwargs))

    def to_string(self):
        return self._name.to_string()

    @property
    def kind(self):
        """
        Returns an enum instance. Returns the same values as the builtin
        :py:attr:`inspect.Parameter.kind`.

        No support for Python < 3.4 anymore.
        """
        if sys.version_info < (3, 5):
            raise NotImplementedError(
                'Python 2 is end-of-life, the new feature is not available for it'
            )
        return self._name.get_kind()
