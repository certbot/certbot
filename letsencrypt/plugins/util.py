"""Plugin utilities."""
import logging
import socket

import psutil
import zope.component

from letsencrypt import interfaces


logger = logging.getLogger(__name__)


def already_listening(port):
    """Check if a process is already listening on the port.

    If so, also tell the user via a display notification.

    .. warning::
        On some operating systems, this function can only usefully be
        run as root.

    :param int port: The TCP port in question.
    :returns: True or False.

    """
    try:
        net_connections = psutil.net_connections()
    except psutil.AccessDenied as error:
        logger.info("Access denied when trying to list network "
                    "connections: %s. Are you root?", error)
        # this function is just a pre-check that often causes false
        # positives and problems in testing (c.f. #680 on Mac, #255
        # generally); we will fail later in bind() anyway
        return False

    listeners = [conn.pid for conn in net_connections
                 if conn.status == 'LISTEN' and
                 conn.type == socket.SOCK_STREAM and
                 conn.laddr[1] == port]
    try:
        socket.socket().bind(('', port))
    except (socket.error):
        names = []
        for pids in listeners:
            names.append(psutil.Process(pids).name()+" (with PID "+str(pids)+")"+" on port "+str(port))

        name = ""
        if len(names) > 1:
            name = " or ".join(names)
        else:
            name = "".join(names)

        display = zope.component.getUtility(interfaces.IDisplay)
        display.notification(
            "The program {0} is already "
            "listening. This will prevent us from binding to "
            "that port. Please stop this program temporarily "
            "and then try again.".format(name))
        return True

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Perhaps the result of a race where the process could have
        # exited or relinquished the port (NoSuchProcess), or the result
        # of an OS policy where we're not allowed to look up the process
        # name (AccessDenied).
        pass
    return False
