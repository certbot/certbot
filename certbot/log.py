"""Logging utilities for Certbot."""
from __future__ import print_function
import logging
import logging.handlers
import os
import sys
import traceback

from acme import messages

from certbot import constants
from certbot import errors
from certbot import util

logger = logging.getLogger(__name__)


class ColoredStreamHandler(logging.StreamHandler):
    """Sends colored logging output to a stream.

    If the specified stream is not a tty, the class works like the
    standard logging.StreamHandler. Default red_level is logging.WARNING.

    :ivar bool colored: True if output should be colored
    :ivar bool red_level: The level at which to output

    """

    def __init__(self, stream=None):
        if sys.version_info < (2, 7):  # pragma: no cover
            logging.StreamHandler.__init__(self, stream)
        else:
            super(ColoredStreamHandler, self).__init__(stream)
        self.colored = (sys.stderr.isatty() if stream is None else
                        stream.isatty())
        self.red_level = logging.WARNING

    def format(self, record):
        """Formats the string representation of record.

        :param logging.LogRecord record: Record to be formatted

        :returns: Formatted, string representation of record
        :rtype: str

        """
        out = (logging.StreamHandler.format(self, record)
               if sys.version_info < (2, 7)
               else super(ColoredStreamHandler, self).format(record))
        if self.colored and record.levelno >= self.red_level:
            return ''.join((util.ANSI_SGR_RED, out, util.ANSI_SGR_RESET))
        else:
            return out


class MemoryHandler(logging.handlers.MemoryHandler):
    """Buffers logging messages in memory until the buffer is flushed.

    This differs from logging.handlers.MemoryHandler in that flushing
    only happens when it is done explicitly.

    """
    def __init__(self, target=None):
        # capacity doesn't matter because should_flush() is overridden
        capacity = float('inf')
        if sys.version_info < (2, 7):  # pragma: no cover
            logging.handlers.MemoryHandler.__init__(
                self, capacity, target=target)
        else:
            super(MemoryHandler, self).__init__(capacity, target=target)

    def shouldFlush(self, record):
        """Should the buffer be automatically flushed?

        :param logging.LogRecord record: log record to be considered

        :returns: False because the buffer should never be auto-flushed
        :rtype: bool

        """
        return False


def except_hook(exc_type, exc_value, unused_trace, debug, log_path):
    """Logs fatal exceptions and reports them to the user.

    If debug is True, the full exception and traceback is shown to the
    user, otherwise, it is suppressed. sys.exit is always called with a
    nonzero status.

    :param type exc_type: type of the raised exception
    :param BaseException exc_value: raised exception
    :param bool debug: True if the traceback should be shown to the user
    :param str log_path: path to file or directory containing the log

    """
    # constants.QUIET_LOGGING_LEVEL or higher should be used to
    # display message the user, otherwise, a lower level like
    # logger.DEBUG should be used
    if debug or not issubclass(exc_type, Exception):
        assert constants.QUIET_LOGGING_LEVEL <= logging.ERROR
        logger.exception('Exiting abnormally:')
    else:
        logger.debug('Exiting abnormally:', exc_info=True)
        if issubclass(exc_type, errors.Error):
            sys.exit(exc_value)
        print('An unexpected error occurred:', file=sys.stderr)
        if messages.is_acme_error(exc_value):
            # Remove the ACME error prefix from the exception
            _, _, exc_str = str(exc_value).partition(':: ')
            print(exc_str, file=sys.stderr)
        else:
            traceback.print_exception(exc_type, exc_value, None)
    exit_with_log_path(log_path)


def exit_with_log_path(log_path):
    """Print a message about the log location and exit.

    The message is printed to stderr and the program will exit with a
    nonzero status.

    :param str log_path: path to file or directory containing the log

    """
    msg = 'Please see the '
    if os.path.isdir(log_path):
        msg += 'logfiles in {0} '.format(log_path)
    else:
        msg += "logfile '{0}' ".format(log_path)
    msg += 'for more details.'
    sys.exit(msg)
