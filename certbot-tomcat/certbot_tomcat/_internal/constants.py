"""Tomcat plugin constants."""
import platform

FREEBSD_DARWIN_SERVER_ROOT = "/root/apache-tomcat-8.5.53"
LINUX_SERVER_ROOT = "/root/apache-tomcat-8.5.53"
WINDOWS_SERVER_ROOT = "C:\apache-tomcat-8.5.53"

if platform.system() in ('FreeBSD', 'Darwin'):
    server_root_tmp = FREEBSD_DARWIN_SERVER_ROOT
elif platform.system() in ('Windows'):
    server_root_tmp = WINDOWS_SERVER_ROOT
else:
    server_root_tmp = LINUX_SERVER_ROOT

CLI_DEFAULTS = dict(
    server_root=server_root_tmp,
    ctl="tomcat",
    service_name=None,
    process_id=None
)
"""CLI defaults."""

def os_constant(key):
    # XXX TODO: In the future, this could return different constants
    #           based on what OS we are running under.  To see an
    #           approach to how to handle different OSes, see the
    #           apache version of this file.  Currently, we do not
    #           actually have any OS-specific constants on Nginx.
    """
    Get a constant value for operating system

    :param key: name of cli constant
    :return: value of constant for active os
    """
    return CLI_DEFAULTS[key]

HSTS_ARGS = ['\"max-age=31536000\"', ' ', 'always']

HEADER_ARGS = {'Strict-Transport-Security': HSTS_ARGS}
