from __future__ import print_function
import sys
from contextlib import contextmanager
from IPython.utils import io
from .__main__ import set_trace
from .__main__ import post_mortem


def update_stdout():
    # setup stdout to ensure output is available with nose
    io.stdout = sys.stdout = sys.__stdout__


def sset_trace(frame=None, context=3):
    update_stdout()
    if frame is None:
        frame = sys._getframe().f_back
    set_trace(frame, context)


def spost_mortem(tb=None):
    update_stdout()
    post_mortem(tb)


def spm():
    spost_mortem(sys.last_traceback)


@contextmanager
def slaunch_ipdb_on_exception():
    try:
        yield
    except Exception:
        e, m, tb = sys.exc_info()
        print(m.__repr__(), file=sys.stderr)
        spost_mortem(tb)
    finally:
        pass
