# A sample distutils script to show to build your own
# extension module which extends pywintypes or pythoncom.
#
# Use 'python setup.py build' to build this extension.
import os
from distutils.core import setup, Extension
from distutils.sysconfig import get_python_lib

sources = ["win32_extension.cpp"]

# Specify the directory where the PyWin32 .h and .lib files are installed.
# If you are doing a win32com extension, you will also need to add
# win32com\Include and win32com\Libs.
ext = Extension("win32_extension", sources,
                include_dirs = [os.path.join(get_python_lib(), "win32", "Include")],
                library_dirs = [os.path.join(get_python_lib(), "win32", "Libs")],
                )

setup(
    name="win32 extension sample", 
    version="0.1",
    ext_modules=[ext],
)
