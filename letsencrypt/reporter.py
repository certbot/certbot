"""Collects and displays information to the user."""
import collections
import logging
import os
import Queue
import sys
import textwrap

import zope.interface

from letsencrypt import interfaces
from letsencrypt import le_util


logger = logging.getLogger(__name__)


class Reporter(object):
    """Collects and displays information to the user.

    :ivar `Queue.PriorityQueue` messages: Messages to be displayed to
        the user.

    """
    zope.interface.implements(interfaces.IReporter)

    HIGH_PRIORITY = 0
    """High priority constant. See `add_message`."""
    MEDIUM_PRIORITY = 1
    """Medium priority constant. See `add_message`."""
    LOW_PRIORITY = 2
    """Low priority constant. See `add_message`."""

    _msg_type = collections.namedtuple('ReporterMsg', 'priority text on_crash')

    def __init__(self):
        self.messages = Queue.PriorityQueue()

    def add_message(self, msg, priority, on_crash=True):
        """Adds msg to the list of messages to be printed.

        :param str msg: Message to be displayed to the user.

        :param int priority: One of `HIGH_PRIORITY`, `MEDIUM_PRIORITY`,
            or `LOW_PRIORITY`.

        :param bool on_crash: Whether or not the message should be
            printed if the program exits abnormally.

        """
        assert self.HIGH_PRIORITY <= priority <= self.LOW_PRIORITY
        self.messages.put(self._msg_type(priority, msg, on_crash))
        logger.info("Reporting to user: %s", msg)

    def atexit_print_messages(self, pid=os.getpid()):
        """Function to be registered with atexit to print messages.

        :param int pid: Process ID

        """
        # This ensures that messages are only printed from the process that
        # created the Reporter.
        if pid == os.getpid():
            self.print_messages()

    def print_messages(self):
        """Prints messages to the user and clears the message queue.

        If there is an unhandled exception, only messages for which
        ``on_crash`` is ``True`` are printed.

        """
        bold_on = False
        if not self.messages.empty():
            no_exception = sys.exc_info()[0] is None
            bold_on = sys.stdout.isatty()
            if bold_on:
                print le_util.ANSI_SGR_BOLD
            print 'IMPORTANT NOTES:'
            first_wrapper = textwrap.TextWrapper(
                initial_indent=' - ', subsequent_indent=(' ' * 3))
            next_wrapper = textwrap.TextWrapper(
                initial_indent=first_wrapper.subsequent_indent,
                subsequent_indent=first_wrapper.subsequent_indent)
        while not self.messages.empty():
            msg = self.messages.get()
            if no_exception or msg.on_crash:
                if bold_on and msg.priority > self.HIGH_PRIORITY:
                    sys.stdout.write(le_util.ANSI_SGR_RESET)
                    bold_on = False
                lines = msg.text.splitlines()
                print first_wrapper.fill(lines[0])
                if len(lines) > 1:
                    print "\n".join(
                        next_wrapper.fill(line) for line in lines[1:])
        if bold_on:
            sys.stdout.write(le_util.ANSI_SGR_RESET)
