import sys
import unittest
import pywintypes
import time
from pywin32_testutil import str2bytes, ob2memory
import datetime
import operator

class TestCase(unittest.TestCase):
    def testPyTimeFormat(self):
        struct_current = time.localtime()
        pytime_current = pywintypes.Time(struct_current)
        # try and test all the standard parts of the format
        # Note we used to include '%Z' testing, but that was pretty useless as
        # it always returned the local timezone.
        format_strings = "%a %A %b %B %c %d %H %I %j %m %M %p %S %U %w %W %x %X %y %Y"
        for fmt in format_strings.split():
            v1 = pytime_current.Format(fmt)
            v2 = time.strftime(fmt, struct_current)
            self.assertEquals(v1, v2, "format %s failed - %r != %r" % (fmt, v1, v2))

    def testPyTimePrint(self):
        # This used to crash with an invalid, or too early time.
        # We don't really want to check that it does cause a ValueError
        # (as hopefully this wont be true forever).  So either working, or 
        # ValueError is OK.
        try:
            t = pywintypes.Time(-2)
            t.Format()
        except ValueError:
            return

    def testTimeInDict(self):
        d = {}
        d['t1'] = pywintypes.Time(1)
        self.failUnlessEqual(d['t1'], pywintypes.Time(1))

    def testPyTimeCompare(self):
        t1 = pywintypes.Time(100)
        t1_2 = pywintypes.Time(100)
        t2 = pywintypes.Time(101)

        self.failUnlessEqual(t1, t1_2)
        self.failUnless(t1 <= t1_2)
        self.failUnless(t1_2 >= t1)

        self.failIfEqual(t1, t2)
        self.failUnless(t1 < t2)
        self.failUnless(t2 > t1 )

    def testPyTimeCompareOther(self):
        t1 = pywintypes.Time(100)
        t2 = None
        self.failIfEqual(t1, t2)

    def testTimeTuple(self):
        now = datetime.datetime.now() # has usec...
        # timetuple() lost usec - pt must be <=...
        pt = pywintypes.Time(now.timetuple())
        # *sob* - only if we have a datetime object can we compare like this.
        if isinstance(pt, datetime.datetime):
            self.failUnless(pt <= now)

    def testTimeTuplems(self):
        now = datetime.datetime.now() # has usec...
        tt = now.timetuple() + (now.microsecond // 1000,)
        pt = pywintypes.Time(tt)
        # we can't compare if using the old type, as it loses all sub-second res.
        if isinstance(pt, datetime.datetime):
            self.failUnlessEqual(now, pt)

    def testPyTimeFromTime(self):
        t1 = pywintypes.Time(time.time())
        self.failUnless(pywintypes.Time(t1) is t1)

    def testPyTimeTooLarge(self):
        # We only do this special thing for python 3.x
        if not issubclass(pywintypes.TimeType, datetime.datetime):
            return
        MAX_TIMESTAMP = 0x7FFFFFFFFFFFFFFF # used by some API function to mean "never"
        ts = pywintypes.TimeStamp(MAX_TIMESTAMP)
        self.failUnlessEqual(ts, datetime.datetime.max)

    def testGUID(self):
        s = "{00020400-0000-0000-C000-000000000046}"
        iid = pywintypes.IID(s)
        iid2 = pywintypes.IID(ob2memory(iid), True)
        self.assertEquals(iid, iid2)
        self.assertRaises(ValueError, pywintypes.IID, str2bytes('00'), True) # too short
        self.assertRaises(TypeError, pywintypes.IID, 0, True) # no buffer

    def testGUIDRichCmp(self):
        s = "{00020400-0000-0000-C000-000000000046}"
        iid = pywintypes.IID(s)
        self.failIf(s==None)
        self.failIf(None==s)
        self.failUnless(s!=None)
        self.failUnless(None!=s)
        if sys.version_info > (3,0):
            self.assertRaises(TypeError, operator.gt, None, s)
            self.assertRaises(TypeError, operator.gt, s, None)
            self.assertRaises(TypeError, operator.lt, None, s)
            self.assertRaises(TypeError, operator.lt, s, None)

    def testGUIDInDict(self):
        s = "{00020400-0000-0000-C000-000000000046}"
        iid = pywintypes.IID(s)
        d = dict(item=iid)
        self.failUnlessEqual(d['item'], iid)

if __name__ == '__main__':
    unittest.main()

