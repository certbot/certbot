"""Logging utilities for Certbot.

The best way to use this module is through `pre_arg_parse_setup` and
`post_arg_parse_setup`. `pre_arg_parse_setup` configures a minimal
terminal logger and ensures a detailed log is written to a secure
temporary file if Certbot exits before `post_arg_parse_setup` is called.
`post_arg_parse_setup` relies on the parsed command line arguments and
does the full logging setup with terminal and rotating file handling as
configured by the user. Any logged messages before
`post_arg_parse_setup` is called are sent to the rotating file handler.
Special care is taken by both methods to ensure all errors are logged
and properly flushed before program exit.

"""
from __future__ import print_function

import functools
import logging
import logging.handlers
import shutil
import sys
import tempfile
import traceback

from acme import messages

from certbot import constants
from certbot import errors
from certbot import util
from certbot.compat import os

# Logging format
CLI_FMT = "%(message)s"
FILE_FMT = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"


logger = logging.getLogger(__name__)


def pre_arg_parse_setup():
    """Setup logging before command line arguments are parsed.

    Terminal logging is setup using
    `certbot.constants.QUIET_LOGGING_LEVEL` so Certbot is as quiet as
    possible. File logging is setup so that logging messages are
    buffered in memory. If Certbot exits before `post_arg_parse_setup`
    is called, these buffered messages are written to a temporary file.
    If Certbot doesn't exit, `post_arg_parse_setup` writes the messages
    to the normal log files.

    This function also sets `logging.shutdown` to be called on program
    exit which automatically flushes logging handlers and
    `sys.excepthook` to properly log/display fatal exceptions.

    """
    temp_handler = TempHandler()
    temp_handler.setFormatter(logging.Formatter(FILE_FMT))
    temp_handler.setLevel(logging.DEBUG)
    memory_handler = MemoryHandler(temp_handler)

    stream_handler = ColoredStreamHandler()
    stream_handler.setFormatter(logging.Formatter(CLI_FMT))
    stream_handler.setLevel(constants.QUIET_LOGGING_LEVEL)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # send all records to handlers
    root_logger.addHandler(memory_handler)
    root_logger.addHandler(stream_handler)

    # logging.shutdown will flush the memory handler because flush() and
    # close() are explicitly called
    util.atexit_register(logging.shutdown)
    sys.excepthook = functools.partial(
        pre_arg_parse_except_hook, memory_handler,
        debug='--debug' in sys.argv, log_path=temp_handler.path)


def post_arg_parse_setup(config):
    """Setup logging after command line arguments are parsed.

    This function assumes `pre_arg_parse_setup` was called earlier and
    the root logging configuration has not been modified. A rotating
    file logging handler is created and the buffered log messages are
    sent to that handler. Terminal logging output is set to the level
    requested by the user.

    :param certbot.interface.IConfig config: Configuration object

    """
    file_handler, file_path = setup_log_file_handler(
        config, 'letsencrypt.log', FILE_FMT)
    logs_dir = os.path.dirname(file_path)

    root_logger = logging.getLogger()
    memory_handler = stderr_handler = None
    for handler in root_logger.handlers:
        if isinstance(handler, ColoredStreamHandler):
            stderr_handler = handler
        elif isinstance(handler, MemoryHandler):
            memory_handler = handler
    msg = 'Previously configured logging handlers have been removed!'
    assert memory_handler is not None and stderr_handler is not None, msg

    root_logger.addHandler(file_handler)
    root_logger.removeHandler(memory_handler)
    temp_handler = memory_handler.target
    memory_handler.setTarget(file_handler)
    memory_handler.flush(force=True)
    memory_handler.close()
    temp_handler.close()

    if config.quiet:
        level = constants.QUIET_LOGGING_LEVEL
    else:
        level = -config.verbose_count * 10
    stderr_handler.setLevel(level)
    logger.debug('Root logging level set at %d', level)
    logger.info('Saving debug log to %s', file_path)

    sys.excepthook = functools.partial(
        post_arg_parse_except_hook, debug=config.debug, log_path=logs_dir)


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
    util.set_up_core_dir(config.logs_dir, 0o700, config.strict_permissions)
    log_file_path = os.path.join(config.logs_dir, logfile)
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file_path, maxBytes=2 ** 20,
            backupCount=config.max_log_backups)
    except IOError as error:
        raise errors.Error(util.PERM_ERR_FMT.format(error))
    # rotate on each invocation, rollover only possible when maxBytes
    # is nonzero and backupCount is nonzero, so we set maxBytes as big
    # as possible not to overrun in single CLI invocation (1MB).
    handler.doRollover()  # TODO: creates empty letsencrypt.log.1 file
    handler.setLevel(logging.DEBUG)
    handler_formatter = logging.Formatter(fmt=fmt)
    handler.setFormatter(handler_formatter)
    return handler, log_file_path


class ColoredStreamHandler(logging.StreamHandler):
    """Sends colored logging output to a stream.

    If the specified stream is not a tty, the class works like the
    standard `logging.StreamHandler`. Default red_level is
    `logging.WARNING`.

    :ivar bool colored: True if output should be colored
    :ivar bool red_level: The level at which to output

    """
    def __init__(self, stream=None):
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
        out = super(ColoredStreamHandler, self).format(record)
        if self.colored and record.levelno >= self.red_level:
            return ''.join((util.ANSI_SGR_RED, out, util.ANSI_SGR_RESET))
        return out


class MemoryHandler(logging.handlers.MemoryHandler):
    """Buffers logging messages in memory until the buffer is flushed.

    This differs from `logging.handlers.MemoryHandler` in that flushing
    only happens when flush(force=True) is called.

    """
    def __init__(self, target=None, capacity=10000):
        # capacity doesn't matter because should_flush() is overridden
        super(MemoryHandler, self).__init__(capacity, target=target)

    def close(self):
        """Close the memory handler, but don't set the target to None."""
        # This allows the logging module which may only have a weak
        # reference to the target handler to properly flush and close it.
        target = self.target
        super(MemoryHandler, self).close()
        self.target = target

    def flush(self, force=False):  # pylint: disable=arguments-differ
        """Flush the buffer if force=True.

        If force=False, this call is a noop.

        :param bool force: True if the buffer should be flushed.

        """
        # This method allows flush() calls in logging.shutdown to be a
        # noop so we can control when this handler is flushed.
        if force:
            super(MemoryHandler, self).flush()

    def shouldFlush(self, record):
        """Should the buffer be automatically flushed?

        :param logging.LogRecord record: log record to be considered

        :returns: False because the buffer should never be auto-flushed
        :rtype: bool

        """
        return False


class TempHandler(logging.StreamHandler):
    """Safely logs messages to a temporary file.

    The file is created with permissions 600. If no log records are sent
    to this handler, the temporary file is deleted when the handler is
    closed.

    :ivar str path: file system path to the temporary log file

    """
    def __init__(self):
        self._workdir = tempfile.mkdtemp()
        self.path = os.path.join(self._workdir, 'log')
        stream = util.safe_open(self.path, mode='w', chmod=0o600)
        super(TempHandler, self).__init__(stream)
        self._delete = True

    def emit(self, record):
        """Log the specified logging record.

        :param logging.LogRecord record: Record to be formatted

        """
        self._delete = False
        super(TempHandler, self).emit(record)

    def close(self):
        """Close the handler and the temporary log file.

        The temporary log file is deleted if it wasn't used.

        """
        self.acquire()
        try:
            # StreamHandler.close() doesn't close the stream to allow a
            # stream like stderr to be used
            self.stream.close()
            if self._delete:
                shutil.rmtree(self._workdir)
            self._delete = False
            super(TempHandler, self).close()
        finally:
            self.release()


def pre_arg_parse_except_hook(memory_handler, *args, **kwargs):
    """A simple wrapper around post_arg_parse_except_hook.

    The additional functionality provided by this wrapper is the memory
    handler will be flushed before Certbot exits. This allows us to
    write logging messages to a temporary file if we crashed before
    logging was fully configured.

    Since sys.excepthook isn't called on SystemExit exceptions, the
    memory handler will not be flushed in this case which prevents us
    from creating temporary log files when argparse exits because a
    command line argument was invalid or -h, --help, or --version was
    provided on the command line.

    :param MemoryHandler memory_handler: memory handler to flush
    :param tuple args: args for post_arg_parse_except_hook
    :param dict kwargs: kwargs for post_arg_parse_except_hook

    """
    try:
        post_arg_parse_except_hook(*args, **kwargs)
    finally:
        # flush() is called here so messages logged during
        # post_arg_parse_except_hook are also flushed.
        memory_handler.flush(force=True)


def post_arg_parse_except_hook(exc_type, exc_value, trace, debug, log_path):
    """Logs fatal exceptions and reports them to the user.

    If debug is True, the full exception and traceback is shown to the
    user, otherwise, it is suppressed. sys.exit is always called with a
    nonzero status.

    :param type exc_type: type of the raised exception
    :param BaseException exc_value: raised exception
    :param traceback trace: traceback of where the exception was raised
    :param bool debug: True if the traceback should be shown to the user
    :param str log_path: path to file or directory containing the log

    """
    exc_info = (exc_type, exc_value, trace)
    # constants.QUIET_LOGGING_LEVEL or higher should be used to
    # display message the user, otherwise, a lower level like
    # logger.DEBUG should be used
    if debug or not issubclass(exc_type, Exception):
        assert constants.QUIET_LOGGING_LEVEL <= logging.ERROR
        logger.error('Exiting abnormally:', exc_info=exc_info)
    else:
        logger.debug('Exiting abnormally:', exc_info=exc_info)
        if issubclass(exc_type, errors.Error):
            sys.exit(exc_value)
        logger.error('An unexpected error occurred:')
        if messages.is_acme_error(exc_value):
            # Remove the ACME error prefix from the exception
            _, _, exc_str = str(exc_value).partition(':: ')
            logger.error(exc_str)
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
