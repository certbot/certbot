# Imported by pywin32.pth to bootstrap the pywin32 environment in "portable"
# environments or any other case where the post-install script isn't run.
#
# In short, there's a directory installed by pywin32 named 'pywin32_system32'
# with some important DLLs which need to be found by Python when some pywin32
# modules are imported.
# If Python has `os.add_dll_directory()`, we need to call it with this path.
# Otherwise, we add this path to PATH.
import os
import site

# The directory should be installed under site-packages.

dirname = os.path.dirname
# This is to get the "...\Lib\site-packages" directory
# out of this file name: "...\Lib\site-packages\win32\Lib\pywin32_bootstrap.py".
# It needs to be searched when installed in virtual environments.
level3_up_dir = dirname(dirname(dirname(__file__)))

site_packages_dirs = getattr(site, "getsitepackages", lambda: [])()
if level3_up_dir not in site_packages_dirs:
    site_packages_dirs.insert(0, level3_up_dir)

for site_packages_dir in site_packages_dirs:
    pywin32_system32 = os.path.join(site_packages_dir, "pywin32_system32")
    if os.path.isdir(pywin32_system32):
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(pywin32_system32)
        else:
            os.environ["PATH"] = pywin32_system32 + os.pathsep + os.environ["PATH"]
        break
