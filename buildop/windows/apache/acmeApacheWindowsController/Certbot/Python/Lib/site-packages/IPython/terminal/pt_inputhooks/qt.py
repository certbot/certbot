import sys
import os
from IPython.external.qt_for_kernel import QtCore, QtGui

# If we create a QApplication, keep a reference to it so that it doesn't get
# garbage collected.
_appref = None
_already_warned = False


def inputhook(context):
    global _appref
    app = QtCore.QCoreApplication.instance()
    if not app:
        if sys.platform == 'linux':
            if not os.environ.get('DISPLAY') \
                    and not os.environ.get('WAYLAND_DISPLAY'):
                import warnings
                global _already_warned
                if not _already_warned:
                    _already_warned = True
                    warnings.warn(
                        'The DISPLAY or WAYLAND_DISPLAY environment variable is '
                        'not set or empty and Qt5 requires this environment '
                        'variable. Deactivate Qt5 code.'
                    )
                return
        _appref = app = QtGui.QApplication([" "])
    event_loop = QtCore.QEventLoop(app)

    if sys.platform == 'win32':
        # The QSocketNotifier method doesn't appear to work on Windows.
        # Use polling instead.
        timer = QtCore.QTimer()
        timer.timeout.connect(event_loop.quit)
        while not context.input_is_ready():
            timer.start(50)  # 50 ms
            event_loop.exec_()
            timer.stop()
    else:
        # On POSIX platforms, we can use a file descriptor to quit the event
        # loop when there is input ready to read.
        notifier = QtCore.QSocketNotifier(context.fileno(),
                                          QtCore.QSocketNotifier.Read)
        try:
            # connect the callback we care about before we turn it on
            notifier.activated.connect(event_loop.exit)
            notifier.setEnabled(True)
            # only start the event loop we are not already flipped
            if not context.input_is_ready():
                event_loop.exec_()
        finally:
            notifier.setEnabled(False)
