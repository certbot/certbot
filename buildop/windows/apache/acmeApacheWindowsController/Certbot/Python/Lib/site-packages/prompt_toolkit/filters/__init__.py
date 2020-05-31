"""
Filters decide whether something is active or not (they decide about a boolean
state). This is used to enable/disable features, like key bindings, parts of
the layout and other stuff. For instance, we could have a `HasSearch` filter
attached to some part of the layout, in order to show that part of the user
interface only while the user is searching.

Filters are made to avoid having to attach callbacks to all event in order to
propagate state. However, they are lazy, they don't automatically propagate the
state of what they are observing. Only when a filter is called (it's actually a
callable), it will calculate its value. So, its not really reactive
programming, but it's made to fit for this framework.

Filters can be chained using ``&`` and ``|`` operations, and inverted using the
``~`` operator, for instance::

    filter = has_focus('default') & ~ has_selection
"""
from .app import *
from .base import Always, Condition, Filter, FilterOrBool, Never
from .cli import *
from .utils import is_true, to_filter
