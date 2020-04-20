"""Backport for `TestCase.assertLogs()`.

Most of the idea and code are from CPython implementation.
https://github.com/python/cpython/blob/b76518d43fb82ed9e5d27025d18c90a23d525c90/Lib/unittest/case.py
"""
import logging
import collections

__all__ = ['AssertLogsMixin']

LoggingWatcher = collections.namedtuple('LoggingWatcher', ['records', 'output'])


class CapturingHandler(logging.Handler):
    """
    A logging handler capturing all (raw and formatted) logging output.
    """

    def __init__(self):
        super(CapturingHandler, self).__init__()
        self.watcher = LoggingWatcher([], [])

    def flush(self):
        pass

    def emit(self, record):
        self.watcher.records.append(record)
        self.watcher.output.append(self.format(record))



class AssertLogsContext(object):
    """
    A context manager used to implement `TestCase.assertLogs()`.
    """

    LOGGING_FORMAT = '%(levelname)s:%(name)s:%(message)s'

    def __init__(self, test_case, logger_name, level):
        self.test_case = test_case

        self.logger_name = logger_name
        self.logger_states = None
        self.logger = None

        if level:
            # pylint: disable=protected-access,no-member
            try:
                # In Python 3.x
                name_to_level = logging._nameToLevel  # type: ignore
            except AttributeError:
                # In Python 2.7
                name_to_level = logging._levelNames  # type: ignore

            self.level = name_to_level.get(level, level)
        else:
            self.level = logging.INFO

        self.watcher = None

    def _save_logger_states(self):
        self.logger_states = (self.logger.handlers[:], self.logger.level, self.logger.propagate)

    def _restore_logger_states(self):
        self.logger.handlers, self.logger.level, self.logger.propagate = self.logger_states

    def __enter__(self):
        if isinstance(self.logger_name, logging.Logger):
            self.logger = self.logger_name
        else:
            self.logger = logging.getLogger(self.logger_name)

        formatter = logging.Formatter(self.LOGGING_FORMAT)

        handler = CapturingHandler()
        handler.setFormatter(formatter)

        self._save_logger_states()
        self.logger.handlers = [handler]
        self.logger.setLevel(self.level)
        self.logger.propagate = False

        self.watcher = handler.watcher
        return handler.watcher

    def __exit__(self, exc_type, exc_value, tb):
        self._restore_logger_states()

        if exc_type is not None:
            # let unexpected exceptions pass through
            return

        if not self.watcher.records:
            self._raiseFailure(
                "no logs of level {} or higher triggered on {}"
                .format(logging.getLevelName(self.level), self.logger.name))

    def _raiseFailure(self, message):
        message = self.test_case._formatMessage(None, message)  # pylint: disable=protected-access
        raise self.test_case.failureException(message)


class AssertLogsMixin(object):
    """
    A mixin that implements `TestCase.assertLogs()`.
    """

    def assertLogs(self, logger=None, level=None):
        """Fail unless a log message of level *level* or higher is emitted
        on *logger_name* or its children.  If omitted, *level* defaults to
        INFO and *logger* defaults to the root logger.
        This method must be used as a context manager, and will yield
        a recording object with two attributes: `output` and `records`.
        At the end of the context manager, the `output` attribute will
        be a list of the matching formatted log messages and the
        `records` attribute will be a list of the corresponding LogRecord
        objects.
        Example::
            with self.assertLogs('foo', level='INFO') as cm:
                logging.getLogger('foo').info('first message')
                logging.getLogger('foo.bar').error('second message')
            self.assertEqual(cm.output, ['INFO:foo:first message',
                                         'ERROR:foo.bar:second message'])
        """
        return AssertLogsContext(self, logger, level)
