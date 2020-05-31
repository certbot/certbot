import unittest
import win32gui
import win32gui_struct
import win32con
import array
import pythoncom

class TestBase(unittest.TestCase):
    def assertDictEquals(self, d, **kw):
        checked = dict()
        for n, v in kw.items():
            self.failUnlessEqual(v, d[n],
                                 "'%s' doesn't match: %r != %r" % (n, v, d[n]))
            checked[n] = True
        checked_keys = list(checked.keys())
        passed_keys = list(kw.keys())
        checked_keys.sort()
        passed_keys.sort()
        self.failUnlessEqual(checked_keys, passed_keys)

class TestMenuItemInfo(TestBase):
    def _testPackUnpack(self, text):
        vals = dict(fType=win32con.MFT_MENUBARBREAK,
                    fState=win32con.MFS_CHECKED,
                    wID=123,
                    hSubMenu=1234,
                    hbmpChecked=12345,
                    hbmpUnchecked=123456,
                    dwItemData=1234567,
                    text=text,
                    hbmpItem=321)
        mii, extras = win32gui_struct.PackMENUITEMINFO(**vals)
        fType, fState, wID, hSubMenu, hbmpChecked, hbmpUnchecked, \
           dwItemData, text, hbmpItem = win32gui_struct.UnpackMENUITEMINFO(mii)
        self.assertDictEquals(vals, fType=fType, fState=fState, wID=wID,
                              hSubMenu=hSubMenu, hbmpChecked=hbmpChecked,
                              hbmpUnchecked=hbmpUnchecked,
                              dwItemData=dwItemData, text=text,
                              hbmpItem=hbmpItem)

    def testPackUnpack(self):
        self._testPackUnpack("Hello")

    def testPackUnpackNone(self):
        self._testPackUnpack(None)

    def testEmptyMenuItemInfo(self):
        mii, extra = win32gui_struct.EmptyMENUITEMINFO()
        fType, fState, wID, hSubMenu, hbmpChecked, hbmpUnchecked, \
           dwItemData, text, hbmpItem = win32gui_struct.UnpackMENUITEMINFO(mii)
        self.failUnlessEqual(fType, 0)
        self.failUnlessEqual(fState, 0)
        self.failUnlessEqual(wID, 0)
        self.failUnlessEqual(hSubMenu, 0)
        self.failUnlessEqual(hbmpChecked, 0)
        self.failUnlessEqual(hbmpUnchecked, 0)
        self.failUnlessEqual(dwItemData, 0)
        self.failUnlessEqual(hbmpItem, 0)
        # it's not clear if UnpackMENUITEMINFO() should ignore cch, instead
        # assuming it is a buffer size rather than 'current length' - but it
        # never has (and this gives us every \0 in the string), and actually
        # helps us test the unicode/str semantics.
        self.failUnlessEqual(text, '\0' * len(text))


class TestMenuInfo(TestBase):
    def testPackUnpack(self):
        vals = dict(dwStyle=1, cyMax=2, hbrBack=3, dwContextHelpID=4,
                    dwMenuData=5)

        mi = win32gui_struct.PackMENUINFO(**vals)
        dwStyle, cyMax, hbrBack, dwContextHelpID, dwMenuData = \
                        win32gui_struct.UnpackMENUINFO(mi)

        self.assertDictEquals(vals, dwStyle=dwStyle, cyMax=cyMax,
                              hbrBack=hbrBack,
                              dwContextHelpID=dwContextHelpID,
                              dwMenuData=dwMenuData)

    def testEmptyMenuItemInfo(self):
        mi = win32gui_struct.EmptyMENUINFO()
        dwStyle, cyMax, hbrBack, dwContextHelpID, dwMenuData = \
                                win32gui_struct.UnpackMENUINFO(mi)
        self.failUnlessEqual(dwStyle, 0)
        self.failUnlessEqual(cyMax, 0)
        self.failUnlessEqual(hbrBack, 0)
        self.failUnlessEqual(dwContextHelpID, 0)
        self.failUnlessEqual(dwMenuData, 0)


class TestTreeViewItem(TestBase):
    def _testPackUnpack(self, text):
        vals = dict(hitem=1, state=2, stateMask=3, text=text, image=4,
                    selimage=5, citems=6, param=7)

        ti, extra = win32gui_struct.PackTVITEM(**vals)
        hitem, state, stateMask, text, image, selimage, citems, param = \
                            win32gui_struct.UnpackTVITEM(ti)

        self.assertDictEquals(vals, hitem=hitem, state=state,
                              stateMask=stateMask, text=text, image=image,
                              selimage=selimage, citems=citems, param=param)

    def testPackUnpack(self):
        self._testPackUnpack("Hello")

    def testPackUnpackNone(self):
        self._testPackUnpack(None)

    def testEmpty(self):
        ti, extras = win32gui_struct.EmptyTVITEM(0)
        hitem, state, stateMask, text, image, selimage, citems, param = \
                            win32gui_struct.UnpackTVITEM(ti)
        self.failUnlessEqual(hitem, 0)
        self.failUnlessEqual(state, 0)
        self.failUnlessEqual(stateMask, 0)
        self.failUnlessEqual(text, '')
        self.failUnlessEqual(image, 0)
        self.failUnlessEqual(selimage, 0)
        self.failUnlessEqual(citems, 0)
        self.failUnlessEqual(param, 0)

class TestListViewItem(TestBase):
    def _testPackUnpack(self, text):
        vals = dict(item=None, subItem=None, state=1, stateMask=2,
                    text=text, image=3, param=4, indent=5)

        ti, extra = win32gui_struct.PackLVITEM(**vals)
        item, subItem, state, stateMask, text, image, param, indent = \
                            win32gui_struct.UnpackLVITEM(ti)

        # patch expected values.
        vals['item'] = 0
        vals['subItem'] = 0
        self.assertDictEquals(vals, item=item, subItem=subItem, state=state,
                              stateMask=stateMask, text=text, image=image,
                              param=param, indent=indent)

    def testPackUnpack(self):
        self._testPackUnpack("Hello")

    def testPackUnpackNone(self):
        self._testPackUnpack(None)

    def testEmpty(self):
        ti, extras = win32gui_struct.EmptyLVITEM(1, 2)
        item, subItem, state, stateMask, text, image, param, indent = \
                            win32gui_struct.UnpackLVITEM(ti)
        self.failUnlessEqual(item, 1)
        self.failUnlessEqual(subItem, 2)
        self.failUnlessEqual(state, 0)
        self.failUnlessEqual(stateMask, 0)
        self.failUnlessEqual(text, '')
        self.failUnlessEqual(image, 0)
        self.failUnlessEqual(param, 0)
        self.failUnlessEqual(indent, 0)


class TestLVColumn(TestBase):
    def _testPackUnpack(self, text):
        vals = dict(fmt=1, cx=2, text=text, subItem=3, image=4, order=5)

        ti, extra = win32gui_struct.PackLVCOLUMN(**vals)
        fmt, cx, text, subItem, image, order = \
                            win32gui_struct.UnpackLVCOLUMN(ti)

        self.assertDictEquals(vals, fmt=fmt, cx=cx, text=text, subItem=subItem,
                              image=image, order=order)

    def testPackUnpack(self):
        self._testPackUnpack("Hello")

    def testPackUnpackNone(self):
        self._testPackUnpack(None)

    def testEmpty(self):
        ti, extras = win32gui_struct.EmptyLVCOLUMN()
        fmt, cx, text, subItem, image, order = \
                            win32gui_struct.UnpackLVCOLUMN(ti)
        self.failUnlessEqual(fmt, 0)
        self.failUnlessEqual(cx, 0)
        self.failUnlessEqual(text, '')
        self.failUnlessEqual(subItem, 0)
        self.failUnlessEqual(image, 0)
        self.failUnlessEqual(order, 0)


class TestDEV_BROADCAST_HANDLE(TestBase):
    def testPackUnpack(self):
        s = win32gui_struct.PackDEV_BROADCAST_HANDLE(123)
        c = array.array("b", s)
        got = win32gui_struct.UnpackDEV_BROADCAST(c.buffer_info()[0])
        self.failUnlessEqual(got.handle, 123)

    def testGUID(self):
        s = win32gui_struct.PackDEV_BROADCAST_HANDLE(123,
                                                     guid=pythoncom.IID_IUnknown)
        c = array.array("b", s)
        got = win32gui_struct.UnpackDEV_BROADCAST(c.buffer_info()[0])
        self.failUnlessEqual(got.handle, 123)
        self.failUnlessEqual(got.eventguid, pythoncom.IID_IUnknown)


class TestDEV_BROADCAST_DEVICEINTERFACE(TestBase):
    def testPackUnpack(self):
        s = win32gui_struct.PackDEV_BROADCAST_DEVICEINTERFACE(pythoncom.IID_IUnknown,
                                                              "hello")
        c = array.array("b", s)
        got = win32gui_struct.UnpackDEV_BROADCAST(c.buffer_info()[0])
        self.failUnlessEqual(got.classguid, pythoncom.IID_IUnknown)
        self.failUnlessEqual(got.name, "hello")


class TestDEV_BROADCAST_VOLUME(TestBase):
    def testPackUnpack(self):
        s = win32gui_struct.PackDEV_BROADCAST_VOLUME(123, 456)
        c = array.array("b", s)
        got = win32gui_struct.UnpackDEV_BROADCAST(c.buffer_info()[0])
        self.failUnlessEqual(got.unitmask, 123)
        self.failUnlessEqual(got.flags, 456)

if __name__=='__main__':
    unittest.main()
