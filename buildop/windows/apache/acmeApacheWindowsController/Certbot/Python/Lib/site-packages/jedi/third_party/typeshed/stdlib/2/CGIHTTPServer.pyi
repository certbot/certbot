# Stubs for CGIHTTPServer (Python 2.7)

from typing import List
import SimpleHTTPServer

class CGIHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    cgi_directories: List[str]
    def do_POST(self) -> None: ...
