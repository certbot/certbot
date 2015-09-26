"""Plugin utilities."""
import socket

import psutil
import zope.component

from letsencrypt import interfaces


def already_listening(port):
    """Check if a process is already listening on the port.

    If so, also tell the user via a display notification.

    .. warning::
        On some operating systems, this function can only usefully be
        run as root.

    :param int port: The TCP port in question.
    :returns: True or False."""

    listeners = [conn.pid for conn in psutil.net_connections()
                 if conn.status == 'LISTEN' and
                 conn.type == socket.SOCK_STREAM and
                 conn.laddr[1] == port]
    try:
        if listeners and listeners[0] is not None:
            # conn.pid may be None if the current process doesn't have
            # permission to identify the listening process!  Additionally,
            # listeners may have more than one element if separate
            # sockets have bound the same port on separate interfaces.
            # We currently only have UI to notify the user about one
            # of them at a time.
            pid = listeners[0]
            name = psutil.Process(pid).name()
            display = zope.component.getUtility(interfaces.IDisplay)
            display.notification(
                "The program {0} (process ID {1}) is already listening "
                "on TCP port {2}. This will prevent us from binding to "
                "that port. Please stop the {0} program temporarily "
                "and then try again.".format(name, pid, port))
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Perhaps the result of a race where the process could have
        # exited or relinquished the port (NoSuchProcess), or the result
        # of an OS policy where we're not allowed to look up the process
        # name (AccessDenied).
        pass
    return False
