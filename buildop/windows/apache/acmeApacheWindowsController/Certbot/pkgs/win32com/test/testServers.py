import pythoncom, win32com.client.dynamic, sys
import winerror
import win32com.test.util
import unittest

def TestConnections():
    import win32com.demos.connect
    win32com.demos.connect.test()

class InterpCase(win32com.test.util.TestCase):
    def setUp(self):
        # Ensure the correct version registered.
        from win32com.test.util import RegisterPythonServer
        from win32com.servers import interp
        RegisterPythonServer(interp.__file__, "Python.Interpreter")

    def _testInterp(self, interp):
        self.assertEquals(interp.Eval("1+1"), 2)
        win32com.test.util.assertRaisesCOM_HRESULT(self, winerror.DISP_E_TYPEMISMATCH,
                                     interp.Eval, 2)

    def testInproc(self):
        interp = win32com.client.dynamic.Dispatch("Python.Interpreter", clsctx = pythoncom.CLSCTX_INPROC)
        self._testInterp(interp)

    def testLocalServer(self):
        interp = win32com.client.dynamic.Dispatch("Python.Interpreter", clsctx = pythoncom.CLSCTX_LOCAL_SERVER)
        self._testInterp(interp)
    
    def testAny(self):
        interp = win32com.client.dynamic.Dispatch("Python.Interpreter")
        self._testInterp(interp)

class ConnectionsTestCase(win32com.test.util.TestCase):
    def testConnections(self):
        TestConnections()
    
if __name__=='__main__':
    unittest.main('testServers')
