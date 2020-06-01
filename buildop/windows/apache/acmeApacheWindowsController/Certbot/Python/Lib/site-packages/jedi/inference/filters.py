"""
Filters are objects that you can use to filter names in different scopes. They
are needed for name resolution.
"""
from abc import abstractmethod
import weakref

from parso.tree import search_ancestor

from jedi._compatibility import use_metaclass
from jedi.inference import flow_analysis
from jedi.inference.base_value import ValueSet, ValueWrapper, \
    LazyValueWrapper
from jedi.parser_utils import get_cached_parent_scope
from jedi.inference.utils import to_list
from jedi.inference.names import TreeNameDefinition, ParamName, \
    AnonymousParamName, AbstractNameDefinition

_definition_name_cache = weakref.WeakKeyDictionary()


class AbstractFilter(object):
    _until_position = None

    def _filter(self, names):
        if self._until_position is not None:
            return [n for n in names if n.start_pos < self._until_position]
        return names

    @abstractmethod
    def get(self, name):
        raise NotImplementedError

    @abstractmethod
    def values(self):
        raise NotImplementedError


class FilterWrapper(object):
    name_wrapper_class = None

    def __init__(self, wrapped_filter):
        self._wrapped_filter = wrapped_filter

    def wrap_names(self, names):
        return [self.name_wrapper_class(name) for name in names]

    def get(self, name):
        return self.wrap_names(self._wrapped_filter.get(name))

    def values(self):
        return self.wrap_names(self._wrapped_filter.values())


def _get_definition_names(used_names, name_key):
    try:
        for_module = _definition_name_cache[used_names]
    except KeyError:
        for_module = _definition_name_cache[used_names] = {}

    try:
        return for_module[name_key]
    except KeyError:
        names = used_names.get(name_key, ())
        result = for_module[name_key] = tuple(
            name for name in names if name.is_definition(include_setitem=True)
        )
        return result


class AbstractUsedNamesFilter(AbstractFilter):
    name_class = TreeNameDefinition

    def __init__(self, parent_context, parser_scope):
        self._parser_scope = parser_scope
        self._module_node = self._parser_scope.get_root_node()
        self._used_names = self._module_node.get_used_names()
        self.parent_context = parent_context

    def get(self, name, **filter_kwargs):
        return self._convert_names(self._filter(
            _get_definition_names(self._used_names, name),
            **filter_kwargs
        ))

    def _convert_names(self, names):
        return [self.name_class(self.parent_context, name) for name in names]

    def values(self, **filter_kwargs):
        return self._convert_names(
            name
            for name_key in self._used_names
            for name in self._filter(
                _get_definition_names(self._used_names, name_key),
                **filter_kwargs
            )
        )

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.parent_context)


class ParserTreeFilter(AbstractUsedNamesFilter):
    def __init__(self, parent_context, node_context=None, until_position=None,
                 origin_scope=None):
        """
        node_context is an option to specify a second value for use cases
        like the class mro where the parent class of a new name would be the
        value, but for some type inference it's important to have a local
        value of the other classes.
        """
        if node_context is None:
            node_context = parent_context
        super(ParserTreeFilter, self).__init__(parent_context, node_context.tree_node)
        self._node_context = node_context
        self._origin_scope = origin_scope
        self._until_position = until_position

    def _filter(self, names):
        names = super(ParserTreeFilter, self)._filter(names)
        names = [n for n in names if self._is_name_reachable(n)]
        return list(self._check_flows(names))

    def _is_name_reachable(self, name):
        parent = name.parent
        if parent.type == 'trailer':
            return False
        base_node = parent if parent.type in ('classdef', 'funcdef') else name
        return get_cached_parent_scope(self._used_names, base_node) == self._parser_scope

    def _check_flows(self, names):
        for name in sorted(names, key=lambda name: name.start_pos, reverse=True):
            check = flow_analysis.reachability_check(
                context=self._node_context,
                value_scope=self._parser_scope,
                node=name,
                origin_scope=self._origin_scope
            )
            if check is not flow_analysis.UNREACHABLE:
                yield name

            if check is flow_analysis.REACHABLE:
                break


class _FunctionExecutionFilter(ParserTreeFilter):
    def __init__(self, parent_context, function_value, until_position, origin_scope):
        super(_FunctionExecutionFilter, self).__init__(
            parent_context,
            until_position=until_position,
            origin_scope=origin_scope,
        )
        self._function_value = function_value

    def _convert_param(self, param, name):
        raise NotImplementedError

    @to_list
    def _convert_names(self, names):
        for name in names:
            param = search_ancestor(name, 'param')
            # Here we don't need to check if the param is a default/annotation,
            # because those are not definitions and never make it to this
            # point.
            if param:
                yield self._convert_param(param, name)
            else:
                yield TreeNameDefinition(self.parent_context, name)


class FunctionExecutionFilter(_FunctionExecutionFilter):
    def __init__(self, *args, **kwargs):
        self._arguments = kwargs.pop('arguments')  # Python 2
        super(FunctionExecutionFilter, self).__init__(*args, **kwargs)

    def _convert_param(self, param, name):
        return ParamName(self._function_value, name, self._arguments)


class AnonymousFunctionExecutionFilter(_FunctionExecutionFilter):
    def _convert_param(self, param, name):
        return AnonymousParamName(self._function_value, name)


class GlobalNameFilter(AbstractUsedNamesFilter):
    def get(self, name):
        try:
            names = self._used_names[name]
        except KeyError:
            return []
        return self._convert_names(self._filter(names))

    @to_list
    def _filter(self, names):
        for name in names:
            if name.parent.type == 'global_stmt':
                yield name

    def values(self):
        return self._convert_names(
            name for name_list in self._used_names.values()
            for name in self._filter(name_list)
        )


class DictFilter(AbstractFilter):
    def __init__(self, dct):
        self._dct = dct

    def get(self, name):
        try:
            value = self._convert(name, self._dct[name])
        except KeyError:
            return []
        else:
            return list(self._filter([value]))

    def values(self):
        def yielder():
            for item in self._dct.items():
                try:
                    yield self._convert(*item)
                except KeyError:
                    pass
        return self._filter(yielder())

    def _convert(self, name, value):
        return value

    def __repr__(self):
        keys = ', '.join(self._dct.keys())
        return '<%s: for {%s}>' % (self.__class__.__name__, keys)


class MergedFilter(object):
    def __init__(self, *filters):
        self._filters = filters

    def get(self, name):
        return [n for filter in self._filters for n in filter.get(name)]

    def values(self):
        return [n for filter in self._filters for n in filter.values()]

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, ', '.join(str(f) for f in self._filters))


class _BuiltinMappedMethod(ValueWrapper):
    """``Generator.__next__`` ``dict.values`` methods and so on."""
    api_type = u'function'

    def __init__(self, value, method, builtin_func):
        super(_BuiltinMappedMethod, self).__init__(builtin_func)
        self._value = value
        self._method = method

    def py__call__(self, arguments):
        # TODO add TypeError if params are given/or not correct.
        return self._method(self._value)


class SpecialMethodFilter(DictFilter):
    """
    A filter for methods that are defined in this module on the corresponding
    classes like Generator (for __next__, etc).
    """
    class SpecialMethodName(AbstractNameDefinition):
        api_type = u'function'

        def __init__(self, parent_context, string_name, value, builtin_value):
            callable_, python_version = value
            if python_version is not None and \
                    python_version != parent_context.inference_state.environment.version_info.major:
                raise KeyError

            self.parent_context = parent_context
            self.string_name = string_name
            self._callable = callable_
            self._builtin_value = builtin_value

        def infer(self):
            for filter in self._builtin_value.get_filters():
                # We can take the first index, because on builtin methods there's
                # always only going to be one name. The same is true for the
                # inferred values.
                for name in filter.get(self.string_name):
                    builtin_func = next(iter(name.infer()))
                    break
                else:
                    continue
                break
            return ValueSet([
                _BuiltinMappedMethod(self.parent_context, self._callable, builtin_func)
            ])

    def __init__(self, value, dct, builtin_value):
        super(SpecialMethodFilter, self).__init__(dct)
        self.value = value
        self._builtin_value = builtin_value
        """
        This value is what will be used to introspect the name, where as the
        other value will be used to execute the function.

        We distinguish, because we have to.
        """

    def _convert(self, name, value):
        return self.SpecialMethodName(self.value, name, value, self._builtin_value)


class _OverwriteMeta(type):
    def __init__(cls, name, bases, dct):
        super(_OverwriteMeta, cls).__init__(name, bases, dct)

        base_dct = {}
        for base_cls in reversed(cls.__bases__):
            try:
                base_dct.update(base_cls.overwritten_methods)
            except AttributeError:
                pass

        for func in cls.__dict__.values():
            try:
                base_dct.update(func.registered_overwritten_methods)
            except AttributeError:
                pass
        cls.overwritten_methods = base_dct


class _AttributeOverwriteMixin(object):
    def get_filters(self, *args, **kwargs):
        yield SpecialMethodFilter(self, self.overwritten_methods, self._wrapped_value)

        for filter in self._wrapped_value.get_filters():
            yield filter


class LazyAttributeOverwrite(use_metaclass(_OverwriteMeta, _AttributeOverwriteMixin,
                                           LazyValueWrapper)):
    def __init__(self, inference_state):
        self.inference_state = inference_state


class AttributeOverwrite(use_metaclass(_OverwriteMeta, _AttributeOverwriteMixin,
                                       ValueWrapper)):
    pass


def publish_method(method_name, python_version_match=None):
    def decorator(func):
        dct = func.__dict__.setdefault('registered_overwritten_methods', {})
        dct[method_name] = func, python_version_match
        return func
    return decorator
