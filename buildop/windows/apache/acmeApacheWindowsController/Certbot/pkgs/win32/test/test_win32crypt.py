# Test module for win32crypt

import unittest
import win32crypt
from pywin32_testutil import str2bytes # py3k-friendly helper


class Crypt(unittest.TestCase):
    def testSimple(self):
        data = str2bytes("My test data")
        entropy = None
        desc = "My description"
        flags = 0
        ps = None
        blob = win32crypt.CryptProtectData(data, desc, entropy, None, ps, flags)
        got_desc, got_data = win32crypt.CryptUnprotectData(blob, entropy, None, ps, flags)
        self.failUnlessEqual(data, got_data)
        self.failUnlessEqual(desc, got_desc)

    def testEntropy(self):
        data = str2bytes("My test data")
        entropy = str2bytes("My test entropy")
        desc = "My description"
        flags = 0
        ps = None
        blob = win32crypt.CryptProtectData(data, desc, entropy, None, ps, flags)
        got_desc, got_data = win32crypt.CryptUnprotectData(blob, entropy, None, ps, flags)
        self.failUnlessEqual(data, got_data)
        self.failUnlessEqual(desc, got_desc)

if __name__ == '__main__':
    unittest.main()
