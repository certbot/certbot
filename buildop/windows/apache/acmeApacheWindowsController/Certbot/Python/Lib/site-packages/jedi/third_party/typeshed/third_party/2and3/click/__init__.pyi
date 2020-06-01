# -*- coding: utf-8 -*-
"""
    click
    ~~~~~

    Click is a simple Python module that wraps the stdlib's optparse to make
    writing command line scripts fun.  Unlike other modules, it's based around
    a simple API that does not come with too much magic and is composable.

    In case optparse ever gets removed from the stdlib, it will be shipped by
    this module.

    :copyright: (c) 2014 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

# Core classes
from .core import (
    Context as Context,
    BaseCommand as BaseCommand,
    Command as Command,
    MultiCommand as MultiCommand,
    Group as Group,
    CommandCollection as CommandCollection,
    Parameter as Parameter,
    Option as Option,
    Argument as Argument,
)

# Globals
from .globals import get_current_context as get_current_context

# Decorators
from .decorators import (
    pass_context as pass_context,
    pass_obj as pass_obj,
    make_pass_decorator as make_pass_decorator,
    command as command,
    group as group,
    argument as argument,
    option as option,
    confirmation_option as confirmation_option,
    password_option as password_option,
    version_option as version_option,
    help_option as help_option,
)

# Types
from .types import (
    ParamType as ParamType,
    File as File,
    FloatRange as FloatRange,
    DateTime as DateTime,
    Path as Path,
    Choice as Choice,
    IntRange as IntRange,
    Tuple as Tuple,
    STRING as STRING,
    INT as INT,
    FLOAT as FLOAT,
    BOOL as BOOL,
    UUID as UUID,
    UNPROCESSED as UNPROCESSED,
)

# Utilities
from .utils import (
    echo as echo,
    get_binary_stream as get_binary_stream,
    get_text_stream as get_text_stream,
    open_file as open_file,
    format_filename as format_filename,
    get_app_dir as get_app_dir,
    get_os_args as get_os_args,
)

# Terminal functions
from .termui import (
    prompt as prompt,
    confirm as confirm,
    get_terminal_size as get_terminal_size,
    echo_via_pager as echo_via_pager,
    progressbar as progressbar,
    clear as clear,
    style as style,
    unstyle as unstyle,
    secho as secho,
    edit as edit,
    launch as launch,
    getchar as getchar,
    pause as pause,
)

# Exceptions
from .exceptions import (
    ClickException as ClickException,
    UsageError as UsageError,
    BadParameter as BadParameter,
    FileError as FileError,
    Abort as Abort,
    NoSuchOption as NoSuchOption,
    BadOptionUsage as BadOptionUsage,
    BadArgumentUsage as BadArgumentUsage,
    MissingParameter as MissingParameter,
)

# Formatting
from .formatting import HelpFormatter as HelpFormatter, wrap_text as wrap_text

# Parsing
from .parser import OptionParser as OptionParser

# Controls if click should emit the warning about the use of unicode
# literals.
disable_unicode_literals_warning: bool


__version__: str
