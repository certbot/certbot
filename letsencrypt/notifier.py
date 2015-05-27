"""Collects and displays information to the user."""
import collections
import Queue
import sys
import textwrap

import zope.interface

from letsencrypt import interfaces


class Notifier(object):
    """Collects and displays information to the user.

    :ivar `Queue.PriorityQueue` messages: Messages to be displayed to the user.

    """

    zope.interface.implements(interfaces.INotify)

    HIGH_PRIORITY, MEDIUM_PRIORITY, LOW_PRIORITY = xrange(3)
    _msg_type = collections.namedtuple('Msg', 'priority, text, on_crash')

    def __init__(self):
        self.messages = Queue.PriorityQueue()

    def add_message(self, msg, priority, on_crash=False):
        """Adds msg to the list of messages to be printed.

        :param str msg: Message to be displayed to the user.

        :param int priority: One of HIGH_PRIORITY, MEDIUM_PRIORITY, or
            LOW_PRIORITY.

        :param bool on_crash: Whether or not the message should be printed if
            the program exits abnormally.

        """
        assert priority >= self.HIGH_PRIORITY and priority <= self.LOW_PRIORITY
        self.messages.put(self._msg_type(priority, msg, on_crash))

    def print_messages(self):
        """Prints messages to the user and clears the message queue.

        If there is an unhandled exception, only messages for which on_crash is
        True are printed.

        """
        if not self.messages.empty():
            no_exception = sys.exc_info()[0] is None
            print 'IMPORTANT NOTES:'
            wrapper = textwrap.TextWrapper(initial_indent=' - ',
                                           subsequent_indent=' '*3)
        while not self.messages.empty():
            msg = self.messages.get()
            if no_exception or msg.on_crash:
                print wrapper.fill(msg.text)
