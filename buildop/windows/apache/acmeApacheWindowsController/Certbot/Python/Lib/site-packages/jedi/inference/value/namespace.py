from jedi.inference.cache import inference_state_method_cache
from jedi.inference.filters import DictFilter
from jedi.inference.names import ValueNameMixin, AbstractNameDefinition
from jedi.inference.base_value import Value
from jedi.inference.value.module import SubModuleDictMixin
from jedi.inference.context import NamespaceContext


class ImplicitNSName(ValueNameMixin, AbstractNameDefinition):
    """
    Accessing names for implicit namespace packages should infer to nothing.
    This object will prevent Jedi from raising exceptions
    """
    def __init__(self, implicit_ns_value, string_name):
        self._value = implicit_ns_value
        self.string_name = string_name


class ImplicitNamespaceValue(Value, SubModuleDictMixin):
    """
    Provides support for implicit namespace packages
    """
    # Is a module like every other module, because if you import an empty
    # folder foobar it will be available as an object:
    # <module 'foobar' (namespace)>.
    api_type = u'module'
    parent_context = None

    def __init__(self, inference_state, string_names, paths):
        super(ImplicitNamespaceValue, self).__init__(inference_state, parent_context=None)
        self.inference_state = inference_state
        self.string_names = string_names
        self._paths = paths

    def get_filters(self, origin_scope=None):
        yield DictFilter(self.sub_modules_dict())

    @property
    @inference_state_method_cache()
    def name(self):
        string_name = self.py__package__()[-1]
        return ImplicitNSName(self, string_name)

    def py__file__(self):
        return None

    def py__package__(self):
        """Return the fullname
        """
        return self.string_names

    def py__path__(self):
        return self._paths

    def py__name__(self):
        return '.'.join(self.string_names)

    def is_namespace(self):
        return True

    def is_stub(self):
        return False

    def is_package(self):
        return True

    def as_context(self):
        return NamespaceContext(self)

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.py__name__())
