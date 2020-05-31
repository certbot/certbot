import unittest

def skipIfNoSecurity(testfunc):
    try:
        import zope.security
    except ImportError: # pragma: no cover
        return unittest.skip("zope.security not installed")(testfunc)
    return testfunc

def fails_if_called(test, msg="This function must not be called.",
                    arguments=True):
    """
    Return a new function (accepting any arguments)
    that will call test.fail(msg) if it is called.

    :keyword bool arguments: If set to ``False``, then we will
        not accept any arguments. This can avoid
        masking when we would expect a TypeError to be raised by
        calling an instance method against a class.
    """
    if not arguments:
        return lambda: test.fail(msg)
    return lambda *_args, **__kwargs: test.fail(msg)
