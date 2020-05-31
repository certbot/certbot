# Stubs for six.moves
#
# Note: Commented out items means they weren't implemented at the time.
# Uncomment them when the modules have been added to the typeshed.
import sys

from io import StringIO as cStringIO
from builtins import filter as filter
from itertools import filterfalse as filterfalse
from builtins import input as input
from sys import intern as intern
from builtins import map as map
from os import getcwd as getcwd
from os import getcwdb as getcwdb
from builtins import range as range
from functools import reduce as reduce
from shlex import quote as shlex_quote
from io import StringIO as StringIO
from collections import UserDict as UserDict
from collections import UserList as UserList
from collections import UserString as UserString
from builtins import range as xrange
from builtins import zip as zip
from itertools import zip_longest as zip_longest
from . import builtins
from . import configparser
# import copyreg as copyreg
# import dbm.gnu as dbm_gnu
from . import _dummy_thread
from . import http_cookiejar
from . import http_cookies
from . import html_entities
from . import html_parser
from . import http_client
from . import email_mime_multipart
from . import email_mime_nonmultipart
from . import email_mime_text
from . import email_mime_base
from . import BaseHTTPServer
from . import CGIHTTPServer
from . import SimpleHTTPServer
from . import cPickle
from . import queue
from . import reprlib
from . import socketserver
from . import _thread
from . import tkinter
from . import tkinter_dialog
from . import tkinter_filedialog
# import tkinter.scrolledtext as tkinter_scrolledtext
# import tkinter.simpledialog as tkinter_simpledialog
# import tkinter.tix as tkinter_tix
from . import tkinter_ttk
from . import tkinter_constants
# import tkinter.dnd as tkinter_dnd
# import tkinter.colorchooser as tkinter_colorchooser
from . import tkinter_commondialog
from . import tkinter_tkfiledialog
# import tkinter.font as tkinter_font
# import tkinter.messagebox as tkinter_messagebox
# import tkinter.simpledialog as tkinter_tksimpledialog
from . import urllib_parse
from . import urllib_error
from . import urllib
from . import urllib_robotparser
# import xmlrpc.client as xmlrpc_client
# import xmlrpc.server as xmlrpc_server

from importlib import reload as reload_module
