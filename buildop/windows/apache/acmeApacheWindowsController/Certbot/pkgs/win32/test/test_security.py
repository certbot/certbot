# Tests for the win32security module.
import sys, os
import unittest
import winerror
from pywin32_testutil import testmain, TestSkipped, ob2memory

import win32api, win32con, win32security, ntsecuritycon

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.pwr_sid=win32security.LookupAccountName('','Power Users')[0]
        self.admin_sid=win32security.LookupAccountName('','Administrator')[0]

    def tearDown(self):
        pass

    def testEqual(self):
        self.failUnlessEqual(win32security.LookupAccountName('','Administrator')[0],
                             win32security.LookupAccountName('','Administrator')[0])

    def testNESID(self):
        self.failUnless(self.pwr_sid==self.pwr_sid)
        self.failUnless(self.pwr_sid!=self.admin_sid)

    def testNEOther(self):
        self.failUnless(self.pwr_sid!=None)
        self.failUnless(None!=self.pwr_sid)
        self.failIf(self.pwr_sid==None)
        self.failIf(None==self.pwr_sid)
        self.failIfEqual(None, self.pwr_sid)

    def testSIDInDict(self):
        d = dict(foo=self.pwr_sid)
        self.failUnlessEqual(d['foo'], self.pwr_sid)

    def testBuffer(self):
        self.failUnlessEqual(ob2memory(win32security.LookupAccountName('','Administrator')[0]),
                             ob2memory(win32security.LookupAccountName('','Administrator')[0]))

    def testMemory(self):
        pwr_sid = self.pwr_sid
        admin_sid = self.admin_sid
        sd1=win32security.SECURITY_DESCRIPTOR()
        sd2=win32security.SECURITY_DESCRIPTOR()
        sd3=win32security.SECURITY_DESCRIPTOR()
        dacl=win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,win32con.GENERIC_READ,pwr_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,win32con.GENERIC_ALL,admin_sid)
        sd4=win32security.SECURITY_DESCRIPTOR()
        sacl=win32security.ACL()
        sacl.AddAuditAccessAce(win32security.ACL_REVISION,win32con.DELETE,admin_sid,1,1)
        sacl.AddAuditAccessAce(win32security.ACL_REVISION,win32con.GENERIC_ALL,pwr_sid,1,1)
        for x in range(0,200000):
            sd1.SetSecurityDescriptorOwner(admin_sid,0)
            sd2.SetSecurityDescriptorGroup(pwr_sid,0)
            sd3.SetSecurityDescriptorDacl(1,dacl,0)
            sd4.SetSecurityDescriptorSacl(1,sacl,0)

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.ds_handle = None
        try:
            # saving the handle means the other test itself should bind faster.
            self.ds_handle = win32security.DsBind()
        except win32security.error as exc:
            if exc.winerror != winerror.ERROR_NO_SUCH_DOMAIN:
                raise
            raise TestSkipped(exc)

    def tearDown(self):
        if self.ds_handle is not None:
            self.ds_handle.close()
    
class TestDS(DomainTests):
    def testDsGetDcName(self):
        # Not sure what we can actually test here!  At least calling it
        # does something :)
        win32security.DsGetDcName()

    def testDsListServerInfo(self):
        # again, not checking much, just exercising the code.
        h=win32security.DsBind()
        for (status, ignore, site) in win32security.DsListSites(h):
            for (status, ignore, server) in win32security.DsListServersInSite(h, site):
                info = win32security.DsListInfoForServer(h, server)
            for (status, ignore, domain) in win32security.DsListDomainsInSite(h, site):
                pass

    def testDsCrackNames(self):
        h = win32security.DsBind()
        fmt_offered = ntsecuritycon.DS_FQDN_1779_NAME
        name = win32api.GetUserNameEx(fmt_offered)
        result = win32security.DsCrackNames(h, 0, fmt_offered, fmt_offered, (name,))
        self.failUnlessEqual(name, result[0][2])

    def testDsCrackNamesSyntax(self):
        # Do a syntax check only - that allows us to avoid binding.
        # But must use DS_CANONICAL_NAME (or _EX)
        expected = win32api.GetUserNameEx(win32api.NameCanonical)
        fmt_offered = ntsecuritycon.DS_FQDN_1779_NAME
        name = win32api.GetUserNameEx(fmt_offered)
        result = win32security.DsCrackNames(None, ntsecuritycon.DS_NAME_FLAG_SYNTACTICAL_ONLY,
                                            fmt_offered, ntsecuritycon.DS_CANONICAL_NAME,
                                            (name,))
        self.failUnlessEqual(expected, result[0][2])

class TestTranslate(DomainTests):
    def _testTranslate(self, fmt_from, fmt_to):
        name = win32api.GetUserNameEx(fmt_from)
        expected = win32api.GetUserNameEx(fmt_to)
        got = win32security.TranslateName(name, fmt_from, fmt_to)
        self.failUnlessEqual(got, expected)

    def testTranslate1(self):
        self._testTranslate(win32api.NameFullyQualifiedDN, win32api.NameSamCompatible)

    def testTranslate2(self):
        self._testTranslate(win32api.NameSamCompatible, win32api.NameFullyQualifiedDN)

    def testTranslate3(self):
        self._testTranslate(win32api.NameFullyQualifiedDN, win32api.NameUniqueId)

    def testTranslate4(self):
        self._testTranslate(win32api.NameUniqueId, win32api.NameFullyQualifiedDN)

if __name__=='__main__':
    testmain()
