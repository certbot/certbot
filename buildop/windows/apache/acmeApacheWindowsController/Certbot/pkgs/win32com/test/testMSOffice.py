# Test MSOffice
#
# Main purpose of test is to ensure that Dynamic COM objects
# work as expected.

# Assumes Word and Excel installed on your machine.

import win32com, sys, string, win32api, traceback
import win32com.client.dynamic
from win32com.test.util import CheckClean
import pythoncom
from win32com.client import gencache
from pywintypes import Unicode

error = "MSOffice test error"

# Test a few of the MSOffice components.
def TestWord():
    # Try and load the object exposed by Word 8
    # Office 97 - _totally_ different object model!
    try:
        # NOTE - using "client.Dispatch" would return an msword8.py instance!
        print("Starting Word 8 for dynamic test")
        word = win32com.client.dynamic.Dispatch("Word.Application")
        TestWord8(word)

        word = None
        # Now we will test Dispatch without the new "lazy" capabilities
        print("Starting Word 8 for non-lazy dynamic test")
        dispatch = win32com.client.dynamic._GetGoodDispatch("Word.Application")
        typeinfo = dispatch.GetTypeInfo()
        attr = typeinfo.GetTypeAttr()
        olerepr = win32com.client.build.DispatchItem(typeinfo, attr, None, 0)
        word = win32com.client.dynamic.CDispatch(dispatch, olerepr)
        dispatch = typeinfo = attr = olerepr = None
        TestWord8(word)

    except pythoncom.com_error:
        print("Starting Word 7 for dynamic test")
        word = win32com.client.Dispatch("Word.Basic")
        TestWord7(word)

    print("Starting MSWord for generated test")
    from win32com.client import gencache
    word = gencache.EnsureDispatch("Word.Application.8")
    TestWord8(word)

def TestWord7(word):
    word.FileNew()
    # If not shown, show the app.
    if not word.AppShow(): word._proc_("AppShow")

    for i in range(12):
        word.FormatFont(Color=i+1, Points=i+12)
        word.Insert("Hello from Python %d\n" % i)

    word.FileClose(2)

def TestWord8(word):
    word.Visible = 1
    doc = word.Documents.Add()
    wrange = doc.Range()
    for i in range(10):
        wrange.InsertAfter("Hello from Python %d\n" % i)
    paras = doc.Paragraphs
    for i in range(len(paras)):
        p = paras[i]()
        p.Font.ColorIndex = i+1
        p.Font.Size = 12 + (4 * i)
    # XXX - note that
    # for para in paras:
    #       para().Font...
    # doesnt seem to work - no error, just doesnt work
    # Should check if it works for VB!
    doc.Close(SaveChanges = 0)
    word.Quit()
    win32api.Sleep(1000) # Wait for word to close, else we
    # may get OA error.

def TestWord8OldStyle():
    try:
        import win32com.test.Generated4Test.msword8
    except ImportError:
        print("Can not do old style test")


def TextExcel(xl):
    xl.Visible = 0
    if xl.Visible: raise error("Visible property is true.")
    xl.Visible = 1
    if not xl.Visible: raise error("Visible property not true.")

    if int(xl.Version[0])>=8:
        xl.Workbooks.Add()
    else:
        xl.Workbooks().Add()


    xl.Range("A1:C1").Value = (1,2,3)
    xl.Range("A2:C2").Value = ('x','y','z')
    xl.Range("A3:C3").Value = ('3','2','1')

    for i in range(20):
        xl.Cells(i+1,i+1).Value = "Hi %d" % i

    if xl.Range("A1").Value != "Hi 0":
        raise error("Single cell range failed")

    if xl.Range("A1:B1").Value != ((Unicode("Hi 0"),2),):
        raise error("flat-horizontal cell range failed")

    if xl.Range("A1:A2").Value != ((Unicode("Hi 0"),),(Unicode("x"),)):
        raise error("flat-vertical cell range failed")

    if xl.Range("A1:C3").Value != ((Unicode("Hi 0"),2,3),(Unicode("x"),Unicode("Hi 1"),Unicode("z")),(3,2,Unicode("Hi 2"))):
        raise error("square cell range failed")

    xl.Range("A1:C3").Value =((3,2,1),("x","y","z"),(1,2,3))

    if xl.Range("A1:C3").Value  != ((3,2,1),(Unicode("x"),Unicode("y"),Unicode("z")),(1,2,3)):
        raise error("Range was not what I set it to!")

    # test dates out with Excel
    xl.Cells(5,1).Value = "Excel time"
    xl.Cells(5,2).Formula = "=Now()"

    import time
    xl.Cells(6,1).Value = "Python time"
    xl.Cells(6,2).Value = pythoncom.MakeTime(time.time())
    xl.Cells(6,2).NumberFormat = "d/mm/yy h:mm"
    xl.Columns("A:B").EntireColumn.AutoFit()

    xl.Workbooks(1).Close(0)
    xl.Quit()

def TestAll():
    TestWord()

    print("Starting Excel for Dynamic test...")
    xl = win32com.client.dynamic.Dispatch("Excel.Application")
    TextExcel(xl)

    try:
        print("Starting Excel 8 for generated excel8.py test...")
        mod = gencache.EnsureModule("{00020813-0000-0000-C000-000000000046}", 0, 1, 2, bForDemand=1)
        xl = win32com.client.Dispatch("Excel.Application")
        TextExcel(xl)
    except ImportError:
        print("Could not import the generated Excel 97 wrapper")

    try:
        import xl5en32
        mod = gencache.EnsureModule("{00020813-0000-0000-C000-000000000046}", 9, 1, 0)
        xl = win32com.client.Dispatch("Excel.Application.5")
        print("Starting Excel 95 for makepy test...")
        TextExcel(xl)
    except ImportError:
        print("Could not import the generated Excel 95 wrapper")

if __name__=='__main__':
    TestAll()
    CheckClean()
    pythoncom.CoUninitialize()
