# Magic utility that "redirects" to pywintypesxx.dll
import imp, sys, os
def __import_pywin32_system_module__(modname, globs):
    # This has been through a number of iterations.  The problem: how to 
    # locate pywintypesXX.dll when it may be in a number of places, and how
    # to avoid ever loading it twice.  This problem is compounded by the
    # fact that the "right" way to do this requires win32api, but this
    # itself requires pywintypesXX.
    # And the killer problem is that someone may have done 'import win32api'
    # before this code is called.  In that case Windows will have already
    # loaded pywintypesXX as part of loading win32api - but by the time
    # we get here, we may locate a different one.  This appears to work, but
    # then starts raising bizarre TypeErrors complaining that something
    # is not a pywintypes type when it clearly is!

    # So in what we hope is the last major iteration of this, we now
    # rely on a _win32sysloader module, implemented in C but not relying
    # on pywintypesXX.dll.  It then can check if the DLL we are looking for
    # lib is already loaded.
    if not sys.platform.startswith("win32"):
        # These extensions can be built on Linux via the 'mainwin' toolkit.
        # Look for a native 'lib{modname}.so'
        # NOTE: The _win32sysloader module will probably build in this
        # environment, so it may be better to use that here too.
        for ext, mode, ext_type in imp.get_suffixes():
            if ext_type==imp.C_EXTENSION:
                for path in sys.path:
                    look = os.path.join(path, "lib" + modname + ext)
                    if os.path.isfile(look):
                        mod = imp.load_module(modname, None, look,
                                              (ext, mode, ext_type))
                        # and fill our namespace with it.
                        # XXX - if this ever moves to py3k, this will probably
                        # need similar adjustments as below...
                        globs.update(mod.__dict__)
                        return
        raise ImportError("No dynamic module " + modname)
    # See if this is a debug build.
    for suffix_item in imp.get_suffixes():
        if suffix_item[0]=='_d.pyd':
            suffix = '_d'
            break
    else:
        suffix = ""
    filename = "%s%d%d%s.dll" % \
               (modname, sys.version_info[0], sys.version_info[1], suffix)
    if hasattr(sys, "frozen"):
        # If we are running from a frozen program (py2exe, McMillan, freeze)
        # then we try and load the DLL from our sys.path
        # XXX - This path may also benefit from _win32sysloader?  However,
        # MarkH has never seen the DLL load problem with py2exe programs...
        for look in sys.path:
            # If the sys.path entry is a (presumably) .zip file, use the
            # directory 
            if os.path.isfile(look):
                look = os.path.dirname(look)            
            found = os.path.join(look, filename)
            if os.path.isfile(found):
                break
        else:
            raise ImportError("Module '%s' isn't in frozen sys.path %s" % (modname, sys.path))
    else:
        # First see if it already in our process - if so, we must use that.
        import _win32sysloader
        found = _win32sysloader.GetModuleFilename(filename)
        if found is None:
            # We ask Windows to load it next.  This is in an attempt to 
            # get the exact same module loaded should pywintypes be imported
            # first (which is how we are here) or if, eg, win32api was imported
            # first thereby implicitly loading the DLL.

            # Sadly though, it doesn't quite work - if pywintypesxx.dll
            # is in system32 *and* the executable's directory, on XP SP2, an
            # import of win32api will cause Windows to load pywintypes
            # from system32, where LoadLibrary for that name will
            # load the one in the exe's dir.
            # That shouldn't really matter though, so long as we only ever
            # get one loaded.
            found = _win32sysloader.LoadModule(filename)
        if found is None:
            # Windows can't find it - which although isn't relevent here, 
            # means that we *must* be the first win32 import, as an attempt
            # to import win32api etc would fail when Windows attempts to 
            # locate the DLL.
            # This is most likely to happen for "non-admin" installs, where
            # we can't put the files anywhere else on the global path.

            # If there is a version in our Python directory, use that
            if os.path.isfile(os.path.join(sys.prefix, filename)):
                found = os.path.join(sys.prefix, filename)
        if found is None:
            # Not in the Python directory?  Maybe we were installed via
            # easy_install...
            if os.path.isfile(os.path.join(os.path.dirname(__file__), filename)):
                found = os.path.join(os.path.dirname(__file__), filename)
        if found is None:
            # We might have been installed via PIP and without the post-install
            # script having been run, so they might be in the
            # lib/site-packages/pywin32_system32 directory.
            # This isn't ideal as it means, say 'python -c "import win32api"'
            # will not work but 'python -c "import pywintypes, win32api"' will,
            # but it's better than nothing...
            import distutils.sysconfig
            maybe = os.path.join(distutils.sysconfig.get_python_lib(plat_specific=1),
                                 "pywin32_system32", filename)
            if os.path.isfile(maybe):
                found = maybe
        if found is None:
            # give up in disgust.
            raise ImportError("No system module '%s' (%s)" % (modname, filename))
    # py2k and py3k differences:
    # On py2k, after doing "imp.load_module('pywintypes')", sys.modules
    # is unchanged - ie, sys.modules['pywintypes'] still refers to *this*
    # .py module - but the module's __dict__ has *already* need updated
    # with the new module's contents.
    # However, on py3k, sys.modules *is* changed - sys.modules['pywintypes']
    # will be changed to the new module object.
    # SO: * on py2k don't need to update any globals.
    #     * on py3k we update our module dict with the new module's dict and
    #       copy its globals to ours.
    old_mod = sys.modules[modname]
    # Python can load the module
    mod = imp.load_dynamic(modname, found)
    # Check the sys.modules[] behaviour we describe above is true...
    if sys.version_info < (3,0):
        assert sys.modules[modname] is old_mod
        assert mod is old_mod
    else:
        assert sys.modules[modname] is not old_mod
        assert sys.modules[modname] is mod
        # as above - re-reset to the *old* module object then update globs.
        sys.modules[modname] = old_mod
        globs.update(mod.__dict__)


__import_pywin32_system_module__("pywintypes", globals())
