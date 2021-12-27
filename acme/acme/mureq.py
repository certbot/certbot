"""
mureq is a replacement for python-requests, intended to be vendored
in-tree by Linux systems software and other lightweight applications.

This is mureq version 0.1.0.

mureq is copyright 2021 by its contributors and is released under the
0BSD ("zero-clause BSD") license.
"""
import contextlib
import io
import os.path
import socket
import ssl
import sys
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection, HTTPMessage, HTTPException

__all__ = ['HTTPException', 'TooManyRedirects', 'Response',
           'yield_response', 'request', 'get', 'post', 'head', 'put', 'patch', 'delete']

DEFAULT_TIMEOUT=15.0

# e.g. "Python 3.8.10"
DEFAULT_UA = "Python " + sys.version.split()[0]


def request(method, url, read_limit=None, **kwargs):
    """request performs an HTTP request and reads the entire response body.

    :param method: HTTP method to request (e.g. 'GET', 'POST')
    :param url: URL to request
    :param read_limit: maximum number of bytes to read from the body, or None for no limit
    :param **kwargs: optional arguments defined by yield_response
    :return: Response object
    :rtype: mureq.Response
    :raises: HTTPException
    """
    with yield_response(method, url, **kwargs) as response:
        try:
            body = response.read(read_limit)
        except IOError as e:
            if isinstance(e, HTTPException):
                raise
            else:
                raise HTTPException(str(e)) from e
        return Response(response.status, _prepare_incoming_headers(response.headers), body)

def get(url, **kwargs):
    """get performs a HTTP GET request."""
    return request('GET', url=url, **kwargs)

def post(url, body=None, **kwargs):
    """post performs a HTTP POST request."""
    return request('POST', url=url, body=body, **kwargs)

def head(url, **kwargs):
    """head performs a HTTP HEAD request."""
    return request('HEAD', url=url, **kwargs)

def put(url, body=None, **kwargs):
    """put performs a HTTP PUT request."""
    return request('PUT', url=url, body=body, **kwargs)

def patch(url, body=None, **kwargs):
    """patch performs a HTTP PATCH request."""
    return request('PATCH', url=url, body=body, **kwargs)

def delete(url, **kwargs):
    """delete performs a HTTP DELETE request."""
    return request('DELETE', url=url, **kwargs)

@contextlib.contextmanager
def yield_response(method, url, *, unix_socket=None, timeout=DEFAULT_TIMEOUT, headers=None, params=None, body=None, form=None, json=None, verify=True, source_address=None, max_redirects=None, ssl_context=None):
    """yield_response is a low-level API that exposes the actual
    http.client.HTTPResponse via a contextmanager.

    Note that unlike mureq.Response, http.client.HTTPResponse does not
    automatically canonicalize multiple appearances of the same header by
    joining them together with a comma delimiter. To retrieve canonicalized
    headers from the response, use response.getheader():
    https://docs.python.org/3/library/http.client.html#http.client.HTTPResponse.getheader

    :param method: HTTP method to request (e.g. 'GET', 'POST')
    :param url: URL to request
    :param unix_socket: path to Unix domain socket to query, or None for a normal TCP request
    :param timeout: timeout in seconds, or None for no timeout (default: 15 seconds)
    :param headers: HTTP headers as a mapping or list of key-value pairs
    :param params: parameters to be URL-encoded and added to the query string, as a mapping or list of key-value pairs
    :param body: payload body of the request; must be bytes
    :param form: parameters to be form-encoded and sent as the payload body, as a mapping or list of key-value pairs
    :param json: str or bytes containing serialized JSON data to be sent as the payload body
    :param verify: bool, whether to verify TLS certificates (default: True)
    :param source_address: source address to bind to for TCP: str, (str, int) pair, or None for default
    :param max_redirects: int, maximum number of redirects to follow, or None (the default) to not follow any redirects
    :param ssl_context: ssl.SSLContext object to control certificate validation, or None to use the default context
    :return: http.client.HTTPResponse (yielded as context manager)
    :rtype: http.client.HTTPResponse
    :raises: HTTPException
    """
    method = method.upper()
    headers = _prepare_outgoing_headers(headers)
    enc_params = _prepare_params(params)
    body = _prepare_body(body, form, json, headers)

    redirected_urls = [url]

    while max_redirects is None or (len(redirected_urls) - 1) <= max_redirects:
        conn, path = _prepare_request(method, url, enc_params=enc_params, timeout=timeout, unix_socket=unix_socket, verify=verify, source_address=source_address, ssl_context=ssl_context)
        try:
            try:
                conn.request(method, path, headers=headers, body=body)
                response = conn.getresponse()
            except IOError as e:
                if isinstance(e, HTTPException):
                    raise
                else:
                    # wrap any IOError that is not already an HTTPException
                    # in HTTPException, exposing a uniform API for remote errors
                    raise HTTPException(str(e)) from e
            redirect_url = _check_redirect(url, response.status, response.headers)
            if max_redirects is None or redirect_url is None:
                yield response
                return
            else:
                redirected_urls.append(redirect_url)
                url = redirect_url
                if response.status == 303:
                    # 303 See Other: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
                    method = 'GET'
        finally:
            conn.close()

    raise TooManyRedirects(redirected_urls)


class Response:
    """Response bundles together the elements of a completely consumed HTTP
    response: the status code (`status_code`, int), the headers
    (`headers`, http.client.HTTPMessage), and the payload body
    (`body`, bytes)."""

    __slots__ = ('status_code', 'headers', 'body')

    def __init__(self, status_code, headers, body):
        self.status_code, self.headers, self.body = status_code, headers, body

    def __repr__(self):
        return "Response(status_code=%d)" % (self.status_code,)

    @property
    def ok(self):
        """ok returns whether the response had a successful status code
        (anything other than a 40x or 50x)."""
        return not (400 <= self.status_code and self.status_code < 600)

    @property
    def content(self):
        """content returns the response body (the `body` member). This is an
        alias for compatibility with requests.Response."""
        # alias for compatibility with requests.Response:
        return self.body

    def _debugstr(self):
        buf = io.StringIO()
        print("HTTP", self.status_code, file=buf)
        for k, v in self.headers.items():
            print("%s: %s" % (k, v), file=buf)
        print(file=buf)
        try:
            print(self.body.decode('utf-8'), file=buf)
        except UnicodeDecodeError:
            print("<%d bytes binary data>" % (len(self.body),), file=buf)
        return buf.getvalue()


class TooManyRedirects(HTTPException):
    """TooManyRedirects is raised when automatic following of redirects was
    enabled, but the server redirected too many times without completing."""
    pass


# end public API, begin internal implementation details

_JSON_CONTENTTYPE = 'application/json'
_FORM_CONTENTTYPE = 'application/x-www-form-urlencoded'


class UnixHTTPConnection(HTTPConnection):
    """UnixHTTPConnection is a subclass of HTTPConnection that connects to a
    Unix domain stream socket instead of a TCP address.
    """

    def __init__(self, path, timeout=DEFAULT_TIMEOUT):
        super(UnixHTTPConnection, self).__init__('localhost', timeout=timeout)
        self._unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._unix_path)
        except:
            sock.close()
            raise
        self.sock = sock

def _check_redirect(url, status, response_headers):
    """Return the URL to redirect to, or None for no redirection."""
    if status not in (301, 302, 303, 307, 308):
        return None
    location = response_headers.get('Location')
    if not location:
        return None
    parsed_location = urllib.parse.urlparse(location)
    if parsed_location.scheme:
        # absolute URL
        return location

    old_url = urllib.parse.urlparse(url)
    if location.startswith('/'):
        # absolute path on old hostname
        return urllib.parse.urlunparse((old_url.scheme, old_url.netloc,
            parsed_location.path, parsed_location.params, parsed_location.query, parsed_location.fragment))

    # relative path on old hostname
    old_dir, _old_file = os.path.split(old_url.path)
    new_path = os.path.join(old_dir, location)
    return urllib.parse.urlunparse((old_url.scheme, old_url.netloc,
        new_path, parsed_location.params, parsed_location.query, parsed_location.fragment))

def _prepare_outgoing_headers(headers):
    if headers is None:
        headers = HTTPMessage()
    elif not isinstance(headers, HTTPMessage):
        new_headers = HTTPMessage()
        if hasattr(headers, 'items'):
            iterator = headers.items()
        else:
            iterator = iter(headers)
        for k, v in iterator:
            new_headers[k] = v
        headers = new_headers
    _setdefault_header(headers, 'User-Agent', DEFAULT_UA)
    return headers

# XXX join multi-headers together so that get(), __getitem__(),
# etc. behave intuitively, then stuff them back in an HTTPMessage.
def _prepare_incoming_headers(headers):
    headers_dict = {}
    for k, v in headers.items():
        headers_dict.setdefault(k, []).append(v)
    result = HTTPMessage()
    # note that iterating over headers_dict preserves the original
    # insertion order in all versions since Python 3.6:
    for k, vlist in headers_dict.items():
        result[k] = ','.join(vlist)
    return result

def _setdefault_header(headers, name, value):
    if name not in headers:
        headers[name] = value

def _prepare_body(body, form, json, headers):
    if body is not None:
        if not isinstance(body, bytes):
            raise TypeError('body must be bytes or None', type(body))
        return body

    if json is not None:
        if isinstance(json, bytes):
            _setdefault_header(headers, 'Content-Type', _JSON_CONTENTTYPE)
            return json
        elif isinstance(json, str):
            _setdefault_header(headers, 'Content-Type', _JSON_CONTENTTYPE)
            return json.encode('utf-8')
        else:
            raise TypeError('json must be str, bytes, or None', type(json))

    if form is not None:
        _setdefault_header(headers, 'Content-Type', _FORM_CONTENTTYPE)
        return urllib.parse.urlencode(form, doseq=True)

    return None

def _prepare_params(params):
    if params is None:
        return ''
    return urllib.parse.urlencode(params, doseq=True)

def _prepare_request(method, url, *, enc_params='', timeout=DEFAULT_TIMEOUT, source_address=None, unix_socket=None, verify=True, ssl_context=None):
    """Parses the URL, returns the path and the right HTTPConnection subclass."""
    parsed_url = urllib.parse.urlparse(url)

    is_unix = (unix_socket is not None)
    scheme = parsed_url.scheme.lower()
    if scheme.endswith('+unix'):
        scheme = scheme[:-5]
        is_unix = True
        if scheme == 'https':
            raise ValueError("https+unix is not implemented")

    if scheme not in ('http', 'https'):
        raise ValueError("unrecognized scheme", scheme)

    is_https = (scheme == 'https')
    host = parsed_url.hostname
    port = 443 if is_https else 80
    if parsed_url.port:
        port = parsed_url.port

    if is_unix and unix_socket is None:
        unix_socket = urllib.parse.unquote(parsed_url.netloc)

    path = parsed_url.path
    if parsed_url.query:
        if enc_params:
            path = '%s?%s&%s' % (path, parsed_url.query, enc_params)
        else:
            path = '%s?%s' % (path, parsed_url.query)
    else:
        if enc_params:
            path = '%s?%s' % (path, enc_params)
        else:
            pass # just parsed_url.path in this case

    if isinstance(source_address, str):
        source_address = (source_address, 0)

    if is_unix:
        conn = UnixHTTPConnection(unix_socket, timeout=timeout)
    elif is_https:
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            if not verify:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
        conn = HTTPSConnection(host, port, source_address=source_address, timeout=timeout,
                               context=ssl_context)
    else:
        conn = HTTPConnection(host, port, source_address=source_address, timeout=timeout)

    return conn, path
