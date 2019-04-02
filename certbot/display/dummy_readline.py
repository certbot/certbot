"""A dummy module with no effect for use on systems without readline."""


def get_completer():
    """An empty implementation of readline.get_completer."""


def get_completer_delims():
    """An empty implementation of readline.get_completer_delims."""


def parse_and_bind(unused_command):  # pylint: disable=unused-argument
    """An empty implementation of readline.parse_and_bind."""


def set_completer(unused_function=None):  # pylint: disable=unused-argument
    """An empty implementation of readline.set_completer."""


def set_completer_delims(unused_delims):  # pylint: disable=unused-argument
    """An empty implementation of readline.set_completer_delims."""
