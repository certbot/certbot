from jedi.inference.base_value import ValueWrapper
from jedi.inference.value.module import ModuleValue
from jedi.inference.filters import ParserTreeFilter
from jedi.inference.names import StubName, StubModuleName
from jedi.inference.gradual.typing import TypingModuleFilterWrapper
from jedi.inference.context import ModuleContext


class StubModuleValue(ModuleValue):
    _module_name_class = StubModuleName

    def __init__(self, non_stub_value_set, *args, **kwargs):
        super(StubModuleValue, self).__init__(*args, **kwargs)
        self.non_stub_value_set = non_stub_value_set

    def is_stub(self):
        return True

    def sub_modules_dict(self):
        """
        We have to overwrite this, because it's possible to have stubs that
        don't have code for all the child modules. At the time of writing this
        there are for example no stubs for `json.tool`.
        """
        names = {}
        for value in self.non_stub_value_set:
            try:
                method = value.sub_modules_dict
            except AttributeError:
                pass
            else:
                names.update(method())
        names.update(super(StubModuleValue, self).sub_modules_dict())
        return names

    def _get_stub_filters(self, origin_scope):
        return [StubFilter(
            parent_context=self.as_context(),
            origin_scope=origin_scope
        )] + list(self.iter_star_filters())

    def get_filters(self, origin_scope=None):
        filters = super(StubModuleValue, self).get_filters(origin_scope)
        next(filters)  # Ignore the first filter and replace it with our own
        stub_filters = self._get_stub_filters(origin_scope=origin_scope)
        for f in stub_filters:
            yield f

        for f in filters:
            yield f

    def _as_context(self):
        return StubModuleContext(self)


class StubModuleContext(ModuleContext):
    def get_filters(self, until_position=None, origin_scope=None):
        # Make sure to ignore the position, because positions are not relevant
        # for stubs.
        return super(StubModuleContext, self).get_filters(origin_scope=origin_scope)


class TypingModuleWrapper(StubModuleValue):
    def get_filters(self, *args, **kwargs):
        filters = super(TypingModuleWrapper, self).get_filters(*args, **kwargs)
        yield TypingModuleFilterWrapper(next(filters))
        for f in filters:
            yield f

    def _as_context(self):
        return TypingModuleContext(self)


class TypingModuleContext(ModuleContext):
    def get_filters(self, *args, **kwargs):
        filters = super(TypingModuleContext, self).get_filters(*args, **kwargs)
        yield TypingModuleFilterWrapper(next(filters))
        for f in filters:
            yield f


class StubFilter(ParserTreeFilter):
    name_class = StubName

    def _is_name_reachable(self, name):
        if not super(StubFilter, self)._is_name_reachable(name):
            return False

        # Imports in stub files are only public if they have an "as"
        # export.
        definition = name.get_definition()
        if definition.type in ('import_from', 'import_name'):
            if name.parent.type not in ('import_as_name', 'dotted_as_name'):
                return False
        n = name.value
        # TODO rewrite direct return
        if n.startswith('_') and not (n.startswith('__') and n.endswith('__')):
            return False
        return True


class VersionInfo(ValueWrapper):
    pass
