=======================
 ``zope.event`` README
=======================

.. image:: https://img.shields.io/pypi/v/zope.event.svg
        :target: https://pypi.python.org/pypi/zope.event/
        :alt: Latest Version

.. image:: https://travis-ci.org/zopefoundation/zope.event.svg?branch=master
        :target: https://travis-ci.org/zopefoundation/zope.event

.. image:: https://readthedocs.org/projects/zopeevent/badge/?version=latest
        :target: http://zopeevent.readthedocs.org/en/latest/
        :alt: Documentation Status

The ``zope.event`` package provides a simple event system, including:

- An event publishing API, intended for use by applications which are
  unaware of any subscribers to their events.

- A very simple event-dispatching system on which more sophisticated
  event dispatching systems can be built. For example, a type-based
  event dispatching system that builds on ``zope.event`` can be found in
  ``zope.component``.

Please see http://zopeevent.readthedocs.io/ for the documentation.

==========================
 ``zope.event`` Changelog
==========================

4.4 (2018-10-05)
================

- Add support for Python 3.7


4.3.0 (2017-07-25)
==================

- Add support for Python 3.6.

- Drop support for Python 3.3.


4.2.0 (2016-02-17)
==================

- Add support for Python 3.5.

- Drop support for Python 2.6 and 3.2.


4.1.0 (2015-10-18)
==================

- Require 100% branch (as well as statement) coverage.

- Add a simple class-based handler implementation.


4.0.3 (2014-03-19)
==================

- Add support for Python 3.4.

- Update ``boostrap.py`` to version 2.2.


4.0.2 (2012-12-31)
==================

- Flesh out PyPI Trove classifiers.

- Add support for jython 2.7.


4.0.1 (2012-11-21)
==================

- Add support for Python 3.3.


4.0.0 (2012-05-16)
==================

- Automate build of Sphinx HTML docs and running doctest snippets via tox.

- Drop explicit support for Python 2.4 / 2.5 / 3.1.

- Add support for PyPy.


3.5.2 (2012-03-30)
==================

- This release is the last which will maintain support for Python 2.4 /
  Python 2.5.

- Add support for continuous integration using ``tox`` and ``jenkins``.

- Add 'setup.py dev' alias (runs ``setup.py develop`` plus installs
  ``nose`` and ``coverage``).

- Add 'setup.py docs' alias (installs ``Sphinx`` and dependencies).


3.5.1 (2011-08-04)
==================

- Add Sphinx documentation.


3.5.0 (2010-05-01)
==================

- Add change log to ``long-description``.

- Add support for Python 3.x.


3.4.1 (2009-03-03)
==================

- A few minor cleanups.


3.4.0 (2007-07-14)
==================

- Initial release as a separate project.


