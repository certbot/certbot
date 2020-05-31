# encoding: utf-8
"""Tests for io.py"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.


import sys
from io import StringIO

from subprocess import Popen, PIPE
import unittest

import nose.tools as nt

from IPython.utils.io import IOStream, Tee, capture_output


def test_tee_simple():
    "Very simple check with stdout only"
    chan = StringIO()
    text = 'Hello'
    tee = Tee(chan, channel='stdout')
    print(text, file=chan)
    nt.assert_equal(chan.getvalue(), text+"\n")


class TeeTestCase(unittest.TestCase):

    def tchan(self, channel):
        trap = StringIO()
        chan = StringIO()
        text = 'Hello'
        
        std_ori = getattr(sys, channel)
        setattr(sys, channel, trap)

        tee = Tee(chan, channel=channel)

        print(text, end='', file=chan)
        trap_val = trap.getvalue()
        nt.assert_equal(chan.getvalue(), text)

        tee.close()

        setattr(sys, channel, std_ori)
        assert getattr(sys, channel) == std_ori

    def test(self):
        for chan in ['stdout', 'stderr']:
            self.tchan(chan)

def test_io_init():
    """Test that io.stdin/out/err exist at startup"""
    for name in ('stdin', 'stdout', 'stderr'):
        cmd = "from IPython.utils import io;print(io.%s.__class__)"%name
        with Popen([sys.executable, '-c', cmd], stdout=PIPE) as p:
            p.wait()
            classname = p.stdout.read().strip().decode('ascii')
        # __class__ is a reference to the class object in Python 3, so we can't
        # just test for string equality.
        assert 'IPython.utils.io.IOStream' in classname, classname

class TestIOStream(unittest.TestCase):

    def test_IOStream_init(self):
        """IOStream initializes from a file-like object missing attributes. """
        # Cause a failure from getattr and dir(). (Issue #6386)
        class BadStringIO(StringIO):
            def __dir__(self):
                attrs = super().__dir__()
                attrs.append('name')
                return attrs
        with self.assertWarns(DeprecationWarning):
            iostream = IOStream(BadStringIO())
            iostream.write('hi, bad iostream\n')

        assert not hasattr(iostream, 'name')
        iostream.close()

    def test_capture_output(self):
        """capture_output() context works"""
        
        with capture_output() as io:
            print('hi, stdout')
            print('hi, stderr', file=sys.stderr)
        
        nt.assert_equal(io.stdout, 'hi, stdout\n')
        nt.assert_equal(io.stderr, 'hi, stderr\n')
