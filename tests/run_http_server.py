import runpy
import sys

# Run Python's built-in HTTP server
# Usage: python ./tests/run_http_server.py port_num
# NOTE: This script should be compatible with 2.6, 2.7, 3.3+

# sys.argv (port number) is passed as-is to the HTTP server module
runpy.run_module(
    'http.server' if sys.version_info[0] == 3 else 'SimpleHTTPServer',
    run_name='__main__')
