===============
 zope.hookable
===============

.. image:: https://img.shields.io/pypi/v/zope.hookable.svg
        :target: https://pypi.python.org/pypi/zope.hookable/
        :alt: Latest release

.. image:: https://img.shields.io/pypi/pyversions/zope.hookable.svg
        :target: https://pypi.org/project/zope.hookable/
        :alt: Supported Python versions

.. image:: https://travis-ci.org/zopefoundation/zope.hookable.svg?branch=master
        :target: https://travis-ci.org/zopefoundation/zope.hookable

.. image:: https://readthedocs.org/projects/zopehookable/badge/?version=latest
        :target: https://zopehookable.readthedocs.io/en/latest/
        :alt: Documentation Status

.. image:: https://coveralls.io/repos/github/zopefoundation/zope.hookable/badge.svg?branch=master
        :target: https://coveralls.io/github/zopefoundation/zope.hookable?branch=master


This package supports the efficient creation of "hookable" objects, which
are callable objects that are meant to be optionally replaced.

The idea is that you create a function that does some default thing and make it
hookable. Later, someone can modify what it does by calling its sethook method
and changing its implementation.  All users of the function, including those
that imported it, will see the change.

Documentation is hosted at https://zopehookable.readthedocs.io


=========
 Changes
=========

4.2.0 (2017-11-07)
==================

- Expose the ``__doc__`` (and, where applicable, ``__bases__`` and
  ``__dict__``) of the hooked object. This lets Sphinx document them.
  See `issue 6 <https://github.com/zopefoundation/zope.hookable/issues/6>`_.

- Respect ``PURE_PYTHON`` at runtime. At build time, always try to
  build the C extensions on supported platforms, but allow it to fail.
  See `issue 7
  <https://github.com/zopefoundation/zope.hookable/issues/7>`_.


4.1.0 (2017-07-26)
==================

- Drop support for Python 2.6, 3.2 and 3.3.

- Add support for Python 3.5 and 3.6.

4.0.4 (2014-03-19)
==================

- Add support for Python 3.4.

4.0.3 (2014-03-17)
==================

- Update ``boostrap.py`` to version 2.2.

- Fix extension compilation on Py3k.

4.0.2 (2012-12-31)
==================

- Flesh out PyPI Trove classifiers.

4.0.1 (2012-11-21)
==================

- Add support for Python 3.3.

- Avoid building the C extension explicitly (use the "feature" indirection
  instead).  https://bugs.launchpad.net/zope.hookable/+bug/1025470

4.0.0 (2012-06-04)
==================

- Add support for PyPy.

- Add support for continuous integration using ``tox`` and ``jenkins``.

- Add a pure-Python reference implementation.

- Move doctests to Sphinx documentation.

- Bring unit test coverage to 100%.

- Add 'setup.py docs' alias (installs ``Sphinx`` and dependencies).

- Add 'setup.py dev' alias (runs ``setup.py develop`` plus installs
  ``nose`` and ``coverage``).

- Drop support for Python 2.4 / 2.5.

- Remove of 'zope.testing.doctestunit' in favor of stdlib's 'doctest.

- Add Python 3 support.

3.4.1 (2009-04-05)
==================

- Update for compatibility with Python 2.6 traceback formats.

- Use Jython-compatible ``bootstrap.py``.

3.4.0 (2007-07-20)
==================

- Initial release as a separate project.


