"""
We need to somehow work with the typing objects. Since the typing objects are
pretty bare we need to add all the Jedi customizations to make them work as
values.

This file deals with all the typing.py cases.
"""
from jedi import debug
from jedi.inference.compiled import builtin_from_name
from jedi.inference.base_value import ValueSet, NO_VALUES, Value, \
    LazyValueWrapper
from jedi.inference.lazy_value import LazyKnownValues
from jedi.inference.arguments import repack_with_argument_clinic
from jedi.inference.filters import FilterWrapper
from jedi.inference.names import NameWrapper, ValueName
from jedi.inference.value.klass import ClassMixin
from jedi.inference.gradual.base import BaseTypingValue, BaseTypingValueWithGenerics
from jedi.inference.gradual.type_var import TypeVarClass
from jedi.inference.gradual.generics import LazyGenericManager, TupleGenericManager

_PROXY_CLASS_TYPES = 'Tuple Generic Protocol Callable Type'.split()
_TYPE_ALIAS_TYPES = {
    'List': 'builtins.list',
    'Dict': 'builtins.dict',
    'Set': 'builtins.set',
    'FrozenSet': 'builtins.frozenset',
    'ChainMap': 'collections.ChainMap',
    'Counter': 'collections.Counter',
    'DefaultDict': 'collections.defaultdict',
    'Deque': 'collections.deque',
}
_PROXY_TYPES = 'Optional Union ClassVar'.split()


class TypingModuleName(NameWrapper):
    def infer(self):
        return ValueSet(self._remap())

    def _remap(self):
        name = self.string_name
        inference_state = self.parent_context.inference_state
        try:
            actual = _TYPE_ALIAS_TYPES[name]
        except KeyError:
            pass
        else:
            yield TypeAlias.create_cached(
                inference_state, self.parent_context, self.tree_name, actual)
            return

        if name in _PROXY_CLASS_TYPES:
            yield ProxyTypingClassValue.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name in _PROXY_TYPES:
            yield ProxyTypingValue.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'runtime':
            # We don't want anything here, not sure what this function is
            # supposed to do, since it just appears in the stubs and shouldn't
            # have any effects there (because it's never executed).
            return
        elif name == 'TypeVar':
            yield TypeVarClass.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'Any':
            yield Any.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'TYPE_CHECKING':
            # This is needed for e.g. imports that are only available for type
            # checking or are in cycles. The user can then check this variable.
            yield builtin_from_name(inference_state, u'True')
        elif name == 'overload':
            yield OverloadFunction.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'NewType':
            yield NewTypeFunction.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'cast':
            yield CastFunction.create_cached(
                inference_state, self.parent_context, self.tree_name)
        elif name == 'TypedDict':
            # TODO doesn't even exist in typeshed/typing.py, yet. But will be
            # added soon.
            pass
        elif name in ('no_type_check', 'no_type_check_decorator'):
            # This is not necessary, as long as we are not doing type checking.
            for c in self._wrapped_name.infer():  # Fuck my life Python 2
                yield c
        else:
            # Everything else shouldn't be relevant for type checking.
            for c in self._wrapped_name.infer():  # Fuck my life Python 2
                yield c


class TypingModuleFilterWrapper(FilterWrapper):
    name_wrapper_class = TypingModuleName


class TypingValueWithIndex(BaseTypingValueWithGenerics):
    def execute_annotation(self):
        string_name = self._tree_name.value

        if string_name == 'Union':
            # This is kind of a special case, because we have Unions (in Jedi
            # ValueSets).
            return self.gather_annotation_classes().execute_annotation()
        elif string_name == 'Optional':
            # Optional is basically just saying it's either None or the actual
            # type.
            return self.gather_annotation_classes().execute_annotation() \
                | ValueSet([builtin_from_name(self.inference_state, u'None')])
        elif string_name == 'Type':
            # The type is actually already given in the index_value
            return self._generics_manager[0]
        elif string_name == 'ClassVar':
            # For now don't do anything here, ClassVars are always used.
            return self._generics_manager[0].execute_annotation()

        mapped = {
            'Tuple': Tuple,
            'Generic': Generic,
            'Protocol': Protocol,
            'Callable': Callable,
        }
        cls = mapped[string_name]
        return ValueSet([cls(
            self.parent_context,
            self._tree_name,
            generics_manager=self._generics_manager,
        )])

    def gather_annotation_classes(self):
        return ValueSet.from_sets(self._generics_manager.to_tuple())

    def _create_instance_with_generics(self, generics_manager):
        return TypingValueWithIndex(
            self.parent_context,
            self._tree_name,
            generics_manager
        )


class ProxyTypingValue(BaseTypingValue):
    index_class = TypingValueWithIndex

    def with_generics(self, generics_tuple):
        return self.index_class.create_cached(
            self.inference_state,
            self.parent_context,
            self._tree_name,
            generics_manager=TupleGenericManager(generics_tuple)
        )

    def py__getitem__(self, index_value_set, contextualized_node):
        return ValueSet(
            self.index_class.create_cached(
                self.inference_state,
                self.parent_context,
                self._tree_name,
                generics_manager=LazyGenericManager(
                    context_of_index=contextualized_node.context,
                    index_value=index_value,
                )
            ) for index_value in index_value_set
        )


class _TypingClassMixin(ClassMixin):
    def py__bases__(self):
        return [LazyKnownValues(
            self.inference_state.builtins_module.py__getattribute__('object')
        )]

    def get_metaclasses(self):
        return []

    @property
    def name(self):
        return ValueName(self, self._tree_name)


class TypingClassValueWithIndex(_TypingClassMixin, TypingValueWithIndex):
    pass


class ProxyTypingClassValue(_TypingClassMixin, ProxyTypingValue):
    index_class = TypingClassValueWithIndex


class TypeAlias(LazyValueWrapper):
    def __init__(self, parent_context, origin_tree_name, actual):
        self.inference_state = parent_context.inference_state
        self.parent_context = parent_context
        self._origin_tree_name = origin_tree_name
        self._actual = actual  # e.g. builtins.list

    @property
    def name(self):
        return ValueName(self, self._origin_tree_name)

    def py__name__(self):
        return self.name.string_name

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self._actual)

    def _get_wrapped_value(self):
        module_name, class_name = self._actual.split('.')
        if self.inference_state.environment.version_info.major == 2 and module_name == 'builtins':
            module_name = '__builtin__'

        # TODO use inference_state.import_module?
        from jedi.inference.imports import Importer
        module, = Importer(
            self.inference_state, [module_name], self.inference_state.builtins_module
        ).follow()
        classes = module.py__getattribute__(class_name)
        # There should only be one, because it's code that we control.
        assert len(classes) == 1, classes
        cls = next(iter(classes))
        return cls

    def gather_annotation_classes(self):
        return ValueSet([self._get_wrapped_value()])


class Callable(BaseTypingValueWithGenerics):
    def py__call__(self, arguments):
        """
            def x() -> Callable[[Callable[..., _T]], _T]: ...
        """
        # The 0th index are the arguments.
        try:
            param_values = self._generics_manager[0]
            result_values = self._generics_manager[1]
        except IndexError:
            debug.warning('Callable[...] defined without two arguments')
            return NO_VALUES
        else:
            from jedi.inference.gradual.annotation import infer_return_for_callable
            return infer_return_for_callable(arguments, param_values, result_values)


class Tuple(LazyValueWrapper):
    def __init__(self, parent_context, name, generics_manager):
        self.inference_state = parent_context.inference_state
        self.parent_context = parent_context
        self._generics_manager = generics_manager

    def _is_homogenous(self):
        # To specify a variable-length tuple of homogeneous type, Tuple[T, ...]
        # is used.
        return self._generics_manager.is_homogenous_tuple()

    def py__simple_getitem__(self, index):
        if self._is_homogenous():
            return self._generics_manager.get_index_and_execute(0)
        else:
            if isinstance(index, int):
                return self._generics_manager.get_index_and_execute(index)

            debug.dbg('The getitem type on Tuple was %s' % index)
            return NO_VALUES

    def py__iter__(self, contextualized_node=None):
        if self._is_homogenous():
            yield LazyKnownValues(self._generics_manager.get_index_and_execute(0))
        else:
            for v in self._generics_manager.to_tuple():
                yield LazyKnownValues(v.execute_annotation())

    def py__getitem__(self, index_value_set, contextualized_node):
        if self._is_homogenous():
            return self._generics_manager.get_index_and_execute(0)

        return ValueSet.from_sets(
            self._generics_manager.to_tuple()
        ).execute_annotation()

    def _get_wrapped_value(self):
        tuple_, = self.inference_state.builtins_module \
            .py__getattribute__('tuple').execute_annotation()
        return tuple_


class Generic(BaseTypingValueWithGenerics):
    pass


class Protocol(BaseTypingValueWithGenerics):
    pass


class Any(BaseTypingValue):
    def execute_annotation(self):
        debug.warning('Used Any - returned no results')
        return NO_VALUES


class OverloadFunction(BaseTypingValue):
    @repack_with_argument_clinic('func, /')
    def py__call__(self, func_value_set):
        # Just pass arguments through.
        return func_value_set


class NewTypeFunction(BaseTypingValue):
    def py__call__(self, arguments):
        ordered_args = arguments.unpack()
        next(ordered_args, (None, None))
        _, second_arg = next(ordered_args, (None, None))
        if second_arg is None:
            return NO_VALUES
        return ValueSet(
            NewType(
                self.inference_state,
                contextualized_node.context,
                contextualized_node.node,
                second_arg.infer(),
            ) for contextualized_node in arguments.get_calling_nodes())


class NewType(Value):
    def __init__(self, inference_state, parent_context, tree_node, type_value_set):
        super(NewType, self).__init__(inference_state, parent_context)
        self._type_value_set = type_value_set
        self.tree_node = tree_node

    def py__call__(self, arguments):
        return self._type_value_set.execute_annotation()

    @property
    def name(self):
        from jedi.inference.compiled.value import CompiledValueName
        return CompiledValueName(self, 'NewType')


class CastFunction(BaseTypingValue):
    @repack_with_argument_clinic('type, object, /')
    def py__call__(self, type_value_set, object_value_set):
        return type_value_set.execute_annotation()
