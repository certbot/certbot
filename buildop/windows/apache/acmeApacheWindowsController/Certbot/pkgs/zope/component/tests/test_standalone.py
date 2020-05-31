##############################################################################
#
# Copyright (c) 2001, 2002, 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Component Architecture Tests
"""
import unittest

from zope.component.tests import skipIfNoSecurity

@skipIfNoSecurity
class StandaloneTests(unittest.TestCase):
    def testStandalone(self):
        # See: https://bugs.launchpad.net/zope3/+bug/98401
        import subprocess
        import sys
        import os
        import pickle

        executable = os.path.abspath(sys.executable)
        where = os.path.dirname(os.path.dirname(__file__))
        program = os.path.join(where, 'standalonetests.py')
        process = subprocess.Popen([executable, program],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE)
        try:
            pickle.dump(sys.path, process.stdin)
            process.stdin.close()

            try:
                rc = process.wait()
            except OSError as e: # pragma: no cover
                # MacIntel raises apparently unimportant EINTR?
                if e.errno != 4:
                    raise # TODO verify sanity of a pass on EINTR :-/
            if rc != 0: # pragma: no cover
                output = process.stdout.read()
                if isinstance(output, bytes):
                    output = output.decode()
                sys.stderr.write('#' * 80 + '\n')
                sys.stdout.write(output)
                sys.stderr.write('#' * 80 + '\n')
                self.fail('Output code: %d' % rc)
        finally:
            process.stdout.close()
