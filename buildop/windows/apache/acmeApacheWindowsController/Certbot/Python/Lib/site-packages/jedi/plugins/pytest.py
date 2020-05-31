from parso.python.tree import search_ancestor
from jedi._compatibility import FileNotFoundError
from jedi.inference.cache import inference_state_method_cache
from jedi.inference.imports import load_module_from_path
from jedi.inference.filters import ParserTreeFilter
from jedi.inference.base_value import NO_VALUES, ValueSet

_PYTEST_FIXTURE_MODULES = [
    ('_pytest', 'monkeypatch'),
    ('_pytest', 'capture'),
    ('_pytest', 'logging'),
    ('_pytest', 'tmpdir'),
    ('_pytest', 'pytester'),
]


def execute(callback):
    def wrapper(value, arguments):
        # This might not be necessary anymore in pytest 4/5, definitely needed
        # for pytest 3.
        if value.py__name__() == 'fixture' \
                and value.parent_context.py__name__() == '_pytest.fixtures':
            return NO_VALUES

        return callback(value, arguments)
    return wrapper


def infer_anonymous_param(func):
    def get_returns(value):
        if value.tree_node.annotation is not None:
            return value.execute_with_values()

        # In pytest we need to differentiate between generators and normal
        # returns.
        # Parameters still need to be anonymous, .as_context() ensures that.
        function_context = value.as_context()
        if function_context.is_generator():
            return function_context.merge_yield_values()
        else:
            return function_context.get_return_values()

    def wrapper(param_name):
        is_pytest_param, param_name_is_function_name = \
            _is_a_pytest_param_and_inherited(param_name)
        if is_pytest_param:
            module = param_name.get_root_context()
            fixtures = _goto_pytest_fixture(
                module,
                param_name.string_name,
                # This skips the current module, because we are basically
                # inheriting a fixture from somewhere else.
                skip_own_module=param_name_is_function_name,
            )
            if fixtures:
                return ValueSet.from_sets(
                    get_returns(value)
                    for fixture in fixtures
                    for value in fixture.infer()
                )
        return func(param_name)
    return wrapper


def goto_anonymous_param(func):
    def wrapper(param_name):
        is_pytest_param, param_name_is_function_name = \
            _is_a_pytest_param_and_inherited(param_name)
        if is_pytest_param:
            names = _goto_pytest_fixture(
                param_name.get_root_context(),
                param_name.string_name,
                skip_own_module=param_name_is_function_name,
            )
            if names:
                return names
        return func(param_name)
    return wrapper


def complete_param_names(func):
    def wrapper(context, func_name, decorator_nodes):
        module_context = context.get_root_context()
        if _is_pytest_func(func_name, decorator_nodes):
            names = []
            for module_context in _iter_pytest_modules(module_context):
                names += FixtureFilter(module_context).values()
            if names:
                return names
        return func(context, func_name, decorator_nodes)
    return wrapper


def _goto_pytest_fixture(module_context, name, skip_own_module):
    for module_context in _iter_pytest_modules(module_context, skip_own_module=skip_own_module):
        names = FixtureFilter(module_context).get(name)
        if names:
            return names


def _is_a_pytest_param_and_inherited(param_name):
    """
    Pytest params are either in a `test_*` function or have a pytest fixture
    with the decorator @pytest.fixture.

    This is a heuristic and will work in most cases.
    """
    funcdef = search_ancestor(param_name.tree_name, 'funcdef')
    if funcdef is None:  # A lambda
        return False, False
    decorators = funcdef.get_decorators()
    return _is_pytest_func(funcdef.name.value, decorators), \
        funcdef.name.value == param_name.string_name


def _is_pytest_func(func_name, decorator_nodes):
    return func_name.startswith('test') \
        or any('fixture' in n.get_code() for n in decorator_nodes)


@inference_state_method_cache()
def _iter_pytest_modules(module_context, skip_own_module=False):
    if not skip_own_module:
        yield module_context

    file_io = module_context.get_value().file_io
    if file_io is not None:
        folder = file_io.get_parent_folder()
        sys_path = module_context.inference_state.get_sys_path()
        while any(folder.path.startswith(p) for p in sys_path):
            file_io = folder.get_file_io('conftest.py')
            if file_io.path != module_context.py__file__():
                try:
                    m = load_module_from_path(module_context.inference_state, file_io)
                    yield m.as_context()
                except FileNotFoundError:
                    pass
            folder = folder.get_parent_folder()

    for names in _PYTEST_FIXTURE_MODULES:
        for module_value in module_context.inference_state.import_module(names):
            yield module_value.as_context()


class FixtureFilter(ParserTreeFilter):
    def _filter(self, names):
        for name in super(FixtureFilter, self)._filter(names):
            funcdef = name.parent
            if funcdef.type == 'funcdef':
                # Class fixtures are not supported
                decorated = funcdef.parent
                if decorated.type == 'decorated' and self._is_fixture(decorated):
                    yield name

    def _is_fixture(self, decorated):
        for decorator in decorated.children:
            dotted_name = decorator.children[1]
            # A heuristic, this makes it faster.
            if 'fixture' in dotted_name.get_code():
                for value in self.parent_context.infer_node(dotted_name):
                    if value.name.get_qualified_names(include_module_names=True) \
                            == ('_pytest', 'fixtures', 'fixture'):
                        return True
        return False
