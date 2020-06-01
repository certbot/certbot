from parso.python import tree

from jedi._compatibility import use_metaclass
from jedi import debug
from jedi.inference.cache import inference_state_method_cache, CachedMetaClass
from jedi.inference import compiled
from jedi.inference import recursion
from jedi.inference import docstrings
from jedi.inference import flow_analysis
from jedi.inference.signature import TreeSignature
from jedi.inference.filters import ParserTreeFilter, FunctionExecutionFilter, \
    AnonymousFunctionExecutionFilter
from jedi.inference.names import ValueName, AbstractNameDefinition, \
    AnonymousParamName, ParamName, NameWrapper
from jedi.inference.base_value import ContextualizedNode, NO_VALUES, \
    ValueSet, TreeValue, ValueWrapper
from jedi.inference.lazy_value import LazyKnownValues, LazyKnownValue, \
    LazyTreeValue
from jedi.inference.context import ValueContext, TreeContextMixin
from jedi.inference.value import iterable
from jedi import parser_utils
from jedi.inference.parser_cache import get_yield_exprs
from jedi.inference.helpers import values_from_qualified_names
from jedi.inference.gradual.generics import TupleGenericManager


class LambdaName(AbstractNameDefinition):
    string_name = '<lambda>'
    api_type = u'function'

    def __init__(self, lambda_value):
        self._lambda_value = lambda_value
        self.parent_context = lambda_value.parent_context

    @property
    def start_pos(self):
        return self._lambda_value.tree_node.start_pos

    def infer(self):
        return ValueSet([self._lambda_value])


class FunctionAndClassBase(TreeValue):
    def get_qualified_names(self):
        if self.parent_context.is_class():
            n = self.parent_context.get_qualified_names()
            if n is None:
                # This means that the parent class lives within a function.
                return None
            return n + (self.py__name__(),)
        elif self.parent_context.is_module():
            return (self.py__name__(),)
        else:
            return None


class FunctionMixin(object):
    api_type = u'function'

    def get_filters(self, origin_scope=None):
        cls = self.py__class__()
        for instance in cls.execute_with_values():
            for filter in instance.get_filters(origin_scope=origin_scope):
                yield filter

    def py__get__(self, instance, class_value):
        from jedi.inference.value.instance import BoundMethod
        if instance is None:
            # Calling the Foo.bar results in the original bar function.
            return ValueSet([self])
        return ValueSet([BoundMethod(instance, class_value.as_context(), self)])

    def get_param_names(self):
        return [AnonymousParamName(self, param.name)
                for param in self.tree_node.get_params()]

    @property
    def name(self):
        if self.tree_node.type == 'lambdef':
            return LambdaName(self)
        return ValueName(self, self.tree_node.name)

    def is_function(self):
        return True

    def py__name__(self):
        return self.name.string_name

    def py__call__(self, arguments):
        function_execution = self.as_context(arguments)
        return function_execution.infer()

    def _as_context(self, arguments=None):
        if arguments is None:
            return AnonymousFunctionExecution(self)
        return FunctionExecutionContext(self, arguments)

    def get_signatures(self):
        return [TreeSignature(f) for f in self.get_signature_functions()]


class FunctionValue(use_metaclass(CachedMetaClass, FunctionMixin, FunctionAndClassBase)):
    @classmethod
    def from_context(cls, context, tree_node):
        def create(tree_node):
            if context.is_class():
                return MethodValue(
                    context.inference_state,
                    context,
                    parent_context=parent_context,
                    tree_node=tree_node
                )
            else:
                return cls(
                    context.inference_state,
                    parent_context=parent_context,
                    tree_node=tree_node
                )

        overloaded_funcs = list(_find_overload_functions(context, tree_node))

        parent_context = context
        while parent_context.is_class() or parent_context.is_instance():
            parent_context = parent_context.parent_context

        function = create(tree_node)

        if overloaded_funcs:
            return OverloadedFunctionValue(
                function,
                # Get them into the correct order: lower line first.
                list(reversed([create(f) for f in overloaded_funcs]))
            )
        return function

    def py__class__(self):
        c, = values_from_qualified_names(self.inference_state, u'types', u'FunctionType')
        return c

    def get_default_param_context(self):
        return self.parent_context

    def get_signature_functions(self):
        return [self]


class FunctionNameInClass(NameWrapper):
    def __init__(self, class_context, name):
        super(FunctionNameInClass, self).__init__(name)
        self._class_context = class_context

    def get_defining_qualified_value(self):
        return self._class_context.get_value()  # Might be None.


class MethodValue(FunctionValue):
    def __init__(self, inference_state, class_context, *args, **kwargs):
        super(MethodValue, self).__init__(inference_state, *args, **kwargs)
        self.class_context = class_context

    def get_default_param_context(self):
        return self.class_context

    def get_qualified_names(self):
        # Need to implement this, because the parent value of a method
        # value is not the class value but the module.
        names = self.class_context.get_qualified_names()
        if names is None:
            return None
        return names + (self.py__name__(),)

    @property
    def name(self):
        return FunctionNameInClass(self.class_context, super(MethodValue, self).name)


class BaseFunctionExecutionContext(ValueContext, TreeContextMixin):
    def is_function_execution(self):
        return True

    def _infer_annotations(self):
        raise NotImplementedError

    @inference_state_method_cache(default=NO_VALUES)
    @recursion.execution_recursion_decorator()
    def get_return_values(self, check_yields=False):
        funcdef = self.tree_node
        if funcdef.type == 'lambdef':
            return self.infer_node(funcdef.children[-1])

        if check_yields:
            value_set = NO_VALUES
            returns = get_yield_exprs(self.inference_state, funcdef)
        else:
            value_set = self._infer_annotations()
            if value_set:
                # If there are annotations, prefer them over anything else.
                # This will make it faster.
                return value_set
            value_set |= docstrings.infer_return_types(self._value)
            returns = funcdef.iter_return_stmts()

        for r in returns:
            check = flow_analysis.reachability_check(self, funcdef, r)
            if check is flow_analysis.UNREACHABLE:
                debug.dbg('Return unreachable: %s', r)
            else:
                if check_yields:
                    value_set |= ValueSet.from_sets(
                        lazy_value.infer()
                        for lazy_value in self._get_yield_lazy_value(r)
                    )
                else:
                    try:
                        children = r.children
                    except AttributeError:
                        ctx = compiled.builtin_from_name(self.inference_state, u'None')
                        value_set |= ValueSet([ctx])
                    else:
                        value_set |= self.infer_node(children[1])
            if check is flow_analysis.REACHABLE:
                debug.dbg('Return reachable: %s', r)
                break
        return value_set

    def _get_yield_lazy_value(self, yield_expr):
        if yield_expr.type == 'keyword':
            # `yield` just yields None.
            ctx = compiled.builtin_from_name(self.inference_state, u'None')
            yield LazyKnownValue(ctx)
            return

        node = yield_expr.children[1]
        if node.type == 'yield_arg':  # It must be a yield from.
            cn = ContextualizedNode(self, node.children[1])
            for lazy_value in cn.infer().iterate(cn):
                yield lazy_value
        else:
            yield LazyTreeValue(self, node)

    @recursion.execution_recursion_decorator(default=iter([]))
    def get_yield_lazy_values(self, is_async=False):
        # TODO: if is_async, wrap yield statements in Awaitable/async_generator_asend
        for_parents = [(y, tree.search_ancestor(y, 'for_stmt', 'funcdef',
                                                'while_stmt', 'if_stmt'))
                       for y in get_yield_exprs(self.inference_state, self.tree_node)]

        # Calculate if the yields are placed within the same for loop.
        yields_order = []
        last_for_stmt = None
        for yield_, for_stmt in for_parents:
            # For really simple for loops we can predict the order. Otherwise
            # we just ignore it.
            parent = for_stmt.parent
            if parent.type == 'suite':
                parent = parent.parent
            if for_stmt.type == 'for_stmt' and parent == self.tree_node \
                    and parser_utils.for_stmt_defines_one_name(for_stmt):  # Simplicity for now.
                if for_stmt == last_for_stmt:
                    yields_order[-1][1].append(yield_)
                else:
                    yields_order.append((for_stmt, [yield_]))
            elif for_stmt == self.tree_node:
                yields_order.append((None, [yield_]))
            else:
                types = self.get_return_values(check_yields=True)
                if types:
                    yield LazyKnownValues(types)
                return
            last_for_stmt = for_stmt

        for for_stmt, yields in yields_order:
            if for_stmt is None:
                # No for_stmt, just normal yields.
                for yield_ in yields:
                    for result in self._get_yield_lazy_value(yield_):
                        yield result
            else:
                input_node = for_stmt.get_testlist()
                cn = ContextualizedNode(self, input_node)
                ordered = cn.infer().iterate(cn)
                ordered = list(ordered)
                for lazy_value in ordered:
                    dct = {str(for_stmt.children[1].value): lazy_value.infer()}
                    with self.predefine_names(for_stmt, dct):
                        for yield_in_same_for_stmt in yields:
                            for result in self._get_yield_lazy_value(yield_in_same_for_stmt):
                                yield result

    def merge_yield_values(self, is_async=False):
        return ValueSet.from_sets(
            lazy_value.infer()
            for lazy_value in self.get_yield_lazy_values()
        )

    def is_generator(self):
        return bool(get_yield_exprs(self.inference_state, self.tree_node))

    def infer(self):
        """
        Created to be used by inheritance.
        """
        inference_state = self.inference_state
        is_coroutine = self.tree_node.parent.type in ('async_stmt', 'async_funcdef')
        from jedi.inference.gradual.base import GenericClass

        if is_coroutine:
            if self.is_generator():
                if inference_state.environment.version_info < (3, 6):
                    return NO_VALUES
                async_generator_classes = inference_state.typing_module \
                    .py__getattribute__('AsyncGenerator')

                yield_values = self.merge_yield_values(is_async=True)
                # The contravariant doesn't seem to be defined.
                generics = (yield_values.py__class__(), NO_VALUES)
                return ValueSet(
                    # In Python 3.6 AsyncGenerator is still a class.
                    GenericClass(c, TupleGenericManager(generics))
                    for c in async_generator_classes
                ).execute_annotation()
            else:
                if inference_state.environment.version_info < (3, 5):
                    return NO_VALUES
                async_classes = inference_state.typing_module.py__getattribute__('Coroutine')
                return_values = self.get_return_values()
                # Only the first generic is relevant.
                generics = (return_values.py__class__(), NO_VALUES, NO_VALUES)
                return ValueSet(
                    GenericClass(c, TupleGenericManager(generics)) for c in async_classes
                ).execute_annotation()
        else:
            if self.is_generator():
                return ValueSet([iterable.Generator(inference_state, self)])
            else:
                return self.get_return_values()


class FunctionExecutionContext(BaseFunctionExecutionContext):
    def __init__(self, function_value, arguments):
        super(FunctionExecutionContext, self).__init__(function_value)
        self._arguments = arguments

    def get_filters(self, until_position=None, origin_scope=None):
        yield FunctionExecutionFilter(
            self, self._value,
            until_position=until_position,
            origin_scope=origin_scope,
            arguments=self._arguments
        )

    def _infer_annotations(self):
        from jedi.inference.gradual.annotation import infer_return_types
        return infer_return_types(self._value, self._arguments)

    def get_param_names(self):
        return [
            ParamName(self._value, param.name, self._arguments)
            for param in self._value.tree_node.get_params()
        ]


class AnonymousFunctionExecution(BaseFunctionExecutionContext):
    def _infer_annotations(self):
        # I don't think inferring anonymous executions is a big thing.
        # Anonymous contexts are mostly there for the user to work in. ~ dave
        return NO_VALUES

    def get_filters(self, until_position=None, origin_scope=None):
        yield AnonymousFunctionExecutionFilter(
            self, self._value,
            until_position=until_position,
            origin_scope=origin_scope,
        )

    def get_param_names(self):
        return self._value.get_param_names()


class OverloadedFunctionValue(FunctionMixin, ValueWrapper):
    def __init__(self, function, overloaded_functions):
        super(OverloadedFunctionValue, self).__init__(function)
        self._overloaded_functions = overloaded_functions

    def py__call__(self, arguments):
        debug.dbg("Execute overloaded function %s", self._wrapped_value, color='BLUE')
        function_executions = []
        for signature in self.get_signatures():
            function_execution = signature.value.as_context(arguments)
            function_executions.append(function_execution)
            if signature.matches_signature(arguments):
                return function_execution.infer()

        if self.inference_state.is_analysis:
            # In this case we want precision.
            return NO_VALUES
        return ValueSet.from_sets(fe.infer() for fe in function_executions)

    def get_signature_functions(self):
        return self._overloaded_functions


def _find_overload_functions(context, tree_node):
    def _is_overload_decorated(funcdef):
        if funcdef.parent.type == 'decorated':
            decorators = funcdef.parent.children[0]
            if decorators.type == 'decorator':
                decorators = [decorators]
            else:
                decorators = decorators.children
            for decorator in decorators:
                dotted_name = decorator.children[1]
                if dotted_name.type == 'name' and dotted_name.value == 'overload':
                    # TODO check with values if it's the right overload
                    return True
        return False

    if tree_node.type == 'lambdef':
        return

    if _is_overload_decorated(tree_node):
        yield tree_node

    while True:
        filter = ParserTreeFilter(
            context,
            until_position=tree_node.start_pos
        )
        names = filter.get(tree_node.name.value)
        assert isinstance(names, list)
        if not names:
            break

        found = False
        for name in names:
            funcdef = name.tree_name.parent
            if funcdef.type == 'funcdef' and _is_overload_decorated(funcdef):
                tree_node = funcdef
                found = True
                yield funcdef

        if not found:
            break
