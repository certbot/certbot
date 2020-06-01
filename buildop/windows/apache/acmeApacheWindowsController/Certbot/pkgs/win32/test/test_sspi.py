# Some tests of the win32security sspi functions.
# Stolen from Roger's original test_sspi.c, a version of which is in "Demos"
# See also the other SSPI demos.
import win32security, sspi, sspicon, win32api
from pywin32_testutil import TestSkipped, testmain, str2bytes
import unittest

# It is quite likely that the Kerberos tests will fail due to not being
# installed.  The NTLM tests do *not* get the same behaviour as they should
# always be there.
def applyHandlingSkips(func, *args):
    try:
        return func(*args)
    except win32api.error as exc:
        if exc.winerror == sspicon.SEC_E_NO_CREDENTIALS:
            raise TestSkipped(exc)
        raise


class TestSSPI(unittest.TestCase):

    def assertRaisesHRESULT(self, hr, func, *args):
        try:
            return func(*args)
            raise RuntimeError("expecting %s failure" % (hr,))
        except win32security.error as exc:
            self.failUnlessEqual(exc.winerror, hr)

    def _doAuth(self, pkg_name):
        sspiclient=sspi.ClientAuth(pkg_name,targetspn=win32api.GetUserName())
        sspiserver=sspi.ServerAuth(pkg_name)

        sec_buffer=None
        err = 1
        while err != 0:
            err, sec_buffer = sspiclient.authorize(sec_buffer)
            err, sec_buffer = sspiserver.authorize(sec_buffer)
        return sspiclient, sspiserver

    def _doTestImpersonate(self, pkg_name):
        # Just for the sake of code exercising!
        sspiclient, sspiserver = self._doAuth(pkg_name)
        sspiserver.ctxt.ImpersonateSecurityContext()
        sspiserver.ctxt.RevertSecurityContext()

    def testImpersonateKerberos(self):
        applyHandlingSkips(self._doTestImpersonate, "Kerberos")

    def testImpersonateNTLM(self):
        self._doTestImpersonate("NTLM")

    def _doTestEncrypt(self, pkg_name):

        sspiclient, sspiserver = self._doAuth(pkg_name)

        pkg_size_info=sspiclient.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        msg=str2bytes('some data to be encrypted ......')

        trailersize=pkg_size_info['SecurityTrailer']
        encbuf=win32security.PySecBufferDescType()
        encbuf.append(win32security.PySecBufferType(len(msg), sspicon.SECBUFFER_DATA))
        encbuf.append(win32security.PySecBufferType(trailersize, sspicon.SECBUFFER_TOKEN))
        encbuf[0].Buffer=msg
        sspiclient.ctxt.EncryptMessage(0,encbuf,1)
        sspiserver.ctxt.DecryptMessage(encbuf,1)
        self.failUnlessEqual(msg, encbuf[0].Buffer)
        # and test the higher-level functions
        data_in = str2bytes("hello")
        data, sig = sspiclient.encrypt(data_in)
        self.assertEqual(sspiserver.decrypt(data, sig), data_in)

        data, sig = sspiserver.encrypt(data_in)
        self.assertEqual(sspiclient.decrypt(data, sig), data_in)

    def testEncryptNTLM(self):
        self._doTestEncrypt("NTLM")
    
    def testEncryptKerberos(self):
        applyHandlingSkips(self._doTestEncrypt, "Kerberos")

    def _doTestSign(self, pkg_name):

        sspiclient, sspiserver = self._doAuth(pkg_name)

        pkg_size_info=sspiclient.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        msg=str2bytes('some data to be encrypted ......')
        
        sigsize=pkg_size_info['MaxSignature']
        sigbuf=win32security.PySecBufferDescType()
        sigbuf.append(win32security.PySecBufferType(len(msg), sspicon.SECBUFFER_DATA))
        sigbuf.append(win32security.PySecBufferType(sigsize, sspicon.SECBUFFER_TOKEN))
        sigbuf[0].Buffer=msg
        sspiclient.ctxt.MakeSignature(0,sigbuf,0)
        sspiserver.ctxt.VerifySignature(sigbuf,0)
        # and test the higher-level functions
        sspiclient.next_seq_num = 1
        sspiserver.next_seq_num = 1
        data = str2bytes("hello")
        key = sspiclient.sign(data)
        sspiserver.verify(data, key)
        key = sspiclient.sign(data)
        self.assertRaisesHRESULT(sspicon.SEC_E_MESSAGE_ALTERED,
                                 sspiserver.verify, data + data, key)

        # and the other way
        key = sspiserver.sign(data)
        sspiclient.verify(data, key)
        key = sspiserver.sign(data)
        self.assertRaisesHRESULT(sspicon.SEC_E_MESSAGE_ALTERED,
                                 sspiclient.verify, data + data, key)

    def testSignNTLM(self):
        self._doTestSign("NTLM")
    
    def testSignKerberos(self):
        applyHandlingSkips(self._doTestSign, "Kerberos")

    def _testSequenceSign(self):
        # Only Kerberos supports sequence detection.
        sspiclient, sspiserver = self._doAuth("Kerberos")
        key = sspiclient.sign("hello")
        sspiclient.sign("hello")
        self.assertRaisesHRESULT(sspicon.SEC_E_OUT_OF_SEQUENCE,
                                 sspiserver.verify, 'hello', key)

    def testSequenceSign(self):
        applyHandlingSkips(self._testSequenceSign)

    def _testSequenceEncrypt(self):
        # Only Kerberos supports sequence detection.
        sspiclient, sspiserver = self._doAuth("Kerberos")
        blob, key = sspiclient.encrypt("hello",)
        blob, key = sspiclient.encrypt("hello")
        self.assertRaisesHRESULT(sspicon.SEC_E_OUT_OF_SEQUENCE,
                                 sspiserver.decrypt, blob, key)

    def testSequenceEncrypt(self):
        applyHandlingSkips(self._testSequenceEncrypt)

if __name__=='__main__':
    testmain()
