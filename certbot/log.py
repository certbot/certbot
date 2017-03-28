"""Logging utilities for Certbot."""
from __future__ import print_function
import functools
import logging
import logging.handlers
import os
import sys
import time
import traceback

from acme import messages

from certbot import cli
from certbot import constants
from certbot import errors
from certbot import util

# Logging format
CLI_FMT = "%(message)s"
FILE_FMT = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"


logger = logging.getLogger(__name__)


def pre_arg_parse_setup():
    """Ensures fatal exceptions are logged and reported to the user."""
    sys.excepthook = functools.partial(except_hook, config=None)


def post_arg_parse_setup(config):
    """Setup logging after command line arguments are parsed.

    :param certbot.interface.IConfig config: Configuration object

    """
    file_handler, file_path = setup_log_file_handler(
        config, 'letsencrypt.log', FILE_FMT)

    if config.quiet:
        level = constants.QUIET_LOGGING_LEVEL
    else:
        level = -config.verbose_count * 10
    stderr_handler = ColoredStreamHandler()
    stderr_handler.setFormatter(logging.Formatter(CLI_FMT))
    stderr_handler.setLevel(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # send all records to handlers
    root_logger.addHandler(stderr_handler)
    root_logger.addHandler(file_handler)

    logger.debug('Root logging level set at %d', level)
    logger.info('Saving debug log to %s', file_path)

    sys.excepthook = functools.partial(except_hook, config=config)


def setup_log_file_handler(config, logfile, fmt):
    """Setup file debug logging.

    :param certbot.interface.IConfig config: Configuration object
    :param str logfile: basename for the log file
    :param str fmt: logging format string

    :returns: file handler and absolute path to the log file
    :rtype: tuple

    """
    # TODO: logs might contain sensitive data such as contents of the
    # private key! #525
    util.make_or_verify_core_dir(
        config.logs_dir, 0o700, os.geteuid(), config.strict_permissions)
    log_file_path = os.path.join(config.logs_dir, logfile)
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file_path, maxBytes=2 ** 20, backupCount=1000)
    except IOError as error:
        raise errors.Error(util.PERM_ERR_FMT.format(error))
    # rotate on each invocation, rollover only possible when maxBytes
    # is nonzero and backupCount is nonzero, so we set maxBytes as big
    # as possible not to overrun in single CLI invocation (1MB).
    handler.doRollover()  # TODO: creates empty letsencrypt.log.1 file
    handler.setLevel(logging.DEBUG)
    handler_formatter = logging.Formatter(fmt=fmt)
    handler_formatter.converter = time.gmtime  # don't use localtime
    handler.setFormatter(handler_formatter)
    return handler, log_file_path


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


def except_hook(exc_type, exc_value, trace, config):
    """Logs exceptions and reports them to the user.

    Config is used to determine how to display exceptions to the user. In
    general, if config.debug is True, then the full exception and traceback is
    shown to the user, otherwise it is suppressed. If config itself is None,
    then the traceback and exception is attempted to be written to a logfile.
    If this is successful, the traceback is suppressed, otherwise it is shown
    to the user. sys.exit is always called with a nonzero status.

    """
    tb_str = "".join(traceback.format_exception(exc_type, exc_value, trace))
    logger.debug("Exiting abnormally:%s%s", os.linesep, tb_str)

    if issubclass(exc_type, Exception) and (config is None or not config.debug):
        if config is None:
            logfile = "certbot.log"
            try:
                with open(logfile, "w") as logfd:
                    traceback.print_exception(
                        exc_type, exc_value, trace, file=logfd)
                assert "--debug" not in sys.argv  # config is None if this explodes
            except:  # pylint: disable=bare-except
                sys.exit(tb_str)
            if "--debug" in sys.argv:
                sys.exit(tb_str)

        if issubclass(exc_type, errors.Error):
            sys.exit(exc_value)
        else:
            # Here we're passing a client or ACME error out to the client at the shell
            # Tell the user a bit about what happened, without overwhelming
            # them with a full traceback
            err = traceback.format_exception_only(exc_type, exc_value)[0]
            # Typical error from the ACME module:
            # acme.messages.Error: urn:ietf:params:acme:error:malformed :: The
            # request message was malformed :: Error creating new registration
            # :: Validation of contact mailto:none@longrandomstring.biz failed:
            # Server failure at resolver
            if (messages.is_acme_error(err) and ":: " in err and
                 config.verbose_count <= cli.flag_default("verbose_count")):
                # prune ACME error code, we have a human description
                _code, _sep, err = err.partition(":: ")
            msg = "An unexpected error occurred:\n" + err + "Please see the "
            if config is None:
                msg += "logfile '{0}' for more details.".format(logfile)
            else:
                msg += "logfiles in {0} for more details.".format(config.logs_dir)
            sys.exit(msg)
    else:
        sys.exit(tb_str)
