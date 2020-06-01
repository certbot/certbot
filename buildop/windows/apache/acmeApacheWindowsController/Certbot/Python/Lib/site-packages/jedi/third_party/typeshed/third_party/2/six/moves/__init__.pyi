# Stubs for six.moves
#
# Note: Commented out items means they weren't implemented at the time.
# Uncomment them when the modules have been added to the typeshed.
from cStringIO import StringIO as cStringIO
from itertools import ifilter as filter
from itertools import ifilterfalse as filterfalse
from __builtin__ import raw_input as input
from __builtin__ import intern as intern
from itertools import imap as map
from os import getcwdu as getcwd
from os import getcwd as getcwdb
from __builtin__ import xrange as range
from __builtin__ import reload as reload_module
from __builtin__ import reduce as reduce
from pipes import quote as shlex_quote
from StringIO import StringIO as StringIO
from UserDict import UserDict as UserDict
from UserList import UserList as UserList
from UserString import UserString as UserString
from __builtin__ import xrange as xrange
from itertools import izip as zip
from itertools import izip_longest as zip_longest
import __builtin__ as builtins
from . import configparser
# import copy_reg as copyreg
# import gdbm as dbm_gnu
from . import _dummy_thread
from . import http_cookiejar
from . import http_cookies
from . import html_entities
from . import html_parser
from . import http_client
# import email.MIMEMultipart as email_mime_multipart
# import email.MIMENonMultipart as email_mime_nonmultipart
from . import email_mime_text
# import email.MIMEBase as email_mime_base
from . import BaseHTTPServer
from . import CGIHTTPServer
from . import SimpleHTTPServer
from . import cPickle
from . import queue
from . import reprlib
from . import socketserver
from . import _thread
# import Tkinter as tkinter
# import Dialog as tkinter_dialog
# import FileDialog as tkinter_filedialog
# import ScrolledText as tkinter_scrolledtext
# import SimpleDialog as tkinter_simpledialog
# import Tix as tkinter_tix
# import ttk as tkinter_ttk
# import Tkconstants as tkinter_constants
# import Tkdnd as tkinter_dnd
# import tkColorChooser as tkinter_colorchooser
# import tkCommonDialog as tkinter_commondialog
# import tkFileDialog as tkinter_tkfiledialog
# import tkFont as tkinter_font
# import tkMessageBox as tkinter_messagebox
# import tkSimpleDialog as tkinter_tksimpledialog
from . import urllib_parse
from . import urllib_error
from . import urllib
from . import urllib_robotparser
from . import xmlrpc_client
# import SimpleXMLRPCServer as xmlrpc_server
