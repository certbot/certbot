"""
prompt_toolkit
==============

Author: Jonathan Slenders

Description: prompt_toolkit is a Library for building powerful interactive
             command lines in Python.  It can be a replacement for GNU
             Readline, but it can be much more than that.

See the examples directory to learn about the usage.

Probably, to get started, you might also want to have a look at
`prompt_toolkit.shortcuts.prompt`.
"""
from .application import Application
from .formatted_text import ANSI, HTML
from .shortcuts import PromptSession, print_formatted_text, prompt

# Don't forget to update in `docs/conf.py`!
__version__ = "3.0.5"

# Version tuple.
VERSION = tuple(__version__.split("."))


__all__ = [
    # Application.
    "Application",
    # Shortcuts.
    "prompt",
    "PromptSession",
    "print_formatted_text",
    # Formatted text.
    "HTML",
    "ANSI",
]
