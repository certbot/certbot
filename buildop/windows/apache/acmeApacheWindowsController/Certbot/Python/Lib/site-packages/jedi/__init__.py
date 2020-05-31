"""
Jedi is a static analysis tool for Python that can be used in IDEs/editors.
Jedi has a focus on autocompletion and goto functionality. Jedi is fast and is
very well tested. It understands Python and stubs on a deep level.

Jedi has support for different goto functions. It's possible to search for
references and list names in a Python file to get information about them.

Jedi uses a very simple API to connect with IDE's. There's a reference
implementation as a `VIM-Plugin <https://github.com/davidhalter/jedi-vim>`_,
which uses Jedi's autocompletion.  We encourage you to use Jedi in your IDEs.
Autocompletion in your REPL is also possible, IPython uses it natively and for
the CPython REPL you have to install it.

Here's a simple example of the autocompletion feature:

>>> import jedi
>>> source = '''
... import json
... json.lo'''
>>> script = jedi.Script(source, path='example.py')
>>> script
<Script: 'example.py' ...>
>>> completions = script.complete(3, len('json.lo'))
>>> completions
[<Completion: load>, <Completion: loads>]
>>> print(completions[0].complete)
ad
>>> print(completions[0].name)
load

As you see Jedi is pretty simple and allows you to concentrate on writing a
good text editor, while still having very good IDE features for Python.
"""

__version__ = '0.16.0'

from jedi.api import Script, Interpreter, set_debug_function, \
    preload_module, names
from jedi import settings
from jedi.api.environment import find_virtualenvs, find_system_environments, \
    get_default_environment, InvalidPythonEnvironment, create_environment, \
    get_system_environment
from jedi.api.exceptions import InternalError
# Finally load the internal plugins. This is only internal.
from jedi.plugins import registry
del registry
