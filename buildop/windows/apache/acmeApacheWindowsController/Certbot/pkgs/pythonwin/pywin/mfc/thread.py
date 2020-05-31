# Thread and application objects

from . import object
import win32ui

class WinThread(object.CmdTarget):
	def __init__(self, initObj = None):
		if initObj is None:
			initObj = win32ui.CreateThread()
		object.CmdTarget.__init__(self, initObj)
		
	def InitInstance(self):
		pass # Default None/0 return indicates success for InitInstance()
	def ExitInstance(self):
		pass
		

class WinApp(WinThread):
	def __init__(self, initApp = None):
		if initApp is None:
			initApp = win32ui.GetApp()
		WinThread.__init__(self, initApp)
