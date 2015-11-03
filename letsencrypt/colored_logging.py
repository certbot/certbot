"""A formatter and StreamHandler for colorizing logging output."""
import logging
import sys

from letsencrypt import le_util


class StreamHandler(logging.StreamHandler):
    """Sends colored logging output to a stream.

    If the specified stream is not a tty, the class works like the
    standard logging.StreamHandler. Default red_level is logging.WARNING.

    :ivar bool colored: True if output should be colored
    :ivar bool red_level: The level at which to output

    """

    def __init__(self, stream=None):
        if sys.version_info < (2, 7):
            # pragma: no cover
            # pylint: disable=non-parent-init-called
            logging.StreamHandler.__init__(self, stream)
        else:
            super(StreamHandler, self).__init__(stream)
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
               else super(StreamHandler, self).format(record))
        if self.colored and record.levelno >= self.red_level:
            return ''.join((le_util.ANSI_SGR_RED, out, le_util.ANSI_SGR_RESET))
        else:
            return out
