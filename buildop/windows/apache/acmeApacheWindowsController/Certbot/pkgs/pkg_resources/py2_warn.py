import sys
import warnings
import textwrap


msg = textwrap.dedent("""
    You are running Setuptools on Python 2, which is no longer
    supported and
    >>> SETUPTOOLS WILL STOP WORKING <<<
    in a subsequent release. Please ensure you are installing
    Setuptools using pip 9.x or later or pin to `setuptools<45`
    in your environment.
    If you have done those things and are still encountering
    this message, please comment in
    https://github.com/pypa/setuptools/issues/1458
    about the steps that led to this unsupported combination.
    """)

sys.version_info < (3,) and warnings.warn("*" * 60 + msg + "*" * 60)
