# Stubs for six.moves.urllib.request
#
# Note: Commented out items means they weren't implemented at the time.
# Uncomment them when the modules have been added to the typeshed.
from urllib.request import urlopen as urlopen
from urllib.request import install_opener as install_opener
from urllib.request import build_opener as build_opener
from urllib.request import pathname2url as pathname2url
from urllib.request import url2pathname as url2pathname
from urllib.request import getproxies as getproxies
from urllib.request import Request as Request
from urllib.request import OpenerDirector as OpenerDirector
from urllib.request import HTTPDefaultErrorHandler as HTTPDefaultErrorHandler
from urllib.request import HTTPRedirectHandler as HTTPRedirectHandler
from urllib.request import HTTPCookieProcessor as HTTPCookieProcessor
from urllib.request import ProxyHandler as ProxyHandler
from urllib.request import BaseHandler as BaseHandler
from urllib.request import HTTPPasswordMgr as HTTPPasswordMgr
from urllib.request import HTTPPasswordMgrWithDefaultRealm as HTTPPasswordMgrWithDefaultRealm
from urllib.request import AbstractBasicAuthHandler as AbstractBasicAuthHandler
from urllib.request import HTTPBasicAuthHandler as HTTPBasicAuthHandler
from urllib.request import ProxyBasicAuthHandler as ProxyBasicAuthHandler
from urllib.request import AbstractDigestAuthHandler as AbstractDigestAuthHandler
from urllib.request import HTTPDigestAuthHandler as HTTPDigestAuthHandler
from urllib.request import ProxyDigestAuthHandler as ProxyDigestAuthHandler
from urllib.request import HTTPHandler as HTTPHandler
from urllib.request import HTTPSHandler as HTTPSHandler
from urllib.request import FileHandler as FileHandler
from urllib.request import FTPHandler as FTPHandler
from urllib.request import CacheFTPHandler as CacheFTPHandler
from urllib.request import UnknownHandler as UnknownHandler
from urllib.request import HTTPErrorProcessor as HTTPErrorProcessor
from urllib.request import urlretrieve as urlretrieve
from urllib.request import urlcleanup as urlcleanup
from urllib.request import URLopener as URLopener
from urllib.request import FancyURLopener as FancyURLopener
# from urllib.request import proxy_bypass as proxy_bypass
from urllib.request import parse_http_list as parse_http_list
from urllib.request import parse_keqv_list as parse_keqv_list
