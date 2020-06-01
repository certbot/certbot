``zope.component``
==================

.. image:: https://img.shields.io/pypi/v/zope.component.svg
    :target: https://pypi.python.org/pypi/zope.component/
    :alt: Latest Version

.. image:: https://travis-ci.org/zopefoundation/zope.component.svg?branch=master
        :target: https://travis-ci.org/zopefoundation/zope.component
        :alt: Build Status

.. image:: https://readthedocs.org/projects/zopecomponent/badge/?version=latest
        :target: http://zopecomponent.readthedocs.org/en/latest/
        :alt: Documentation Status

.. image:: https://coveralls.io/repos/github/zopefoundation/zope.component/badge.svg?branch=master
        :target: https://coveralls.io/github/zopefoundation/zope.component?branch=master
        :alt: Coverage Status


.. note::

   This package is intended to be independently reusable in any Python
   project. It is maintained by the
   `Zope Toolkit project <http://docs.zope.org/zopetoolkit/>`_.

This package represents the core of the Zope Component Architecture.
Together with the zope.interface_ package, it provides facilities for
defining, registering and looking up components.

Please see https://zopecomponent.readthedocs.io/en/latest/ for the
documentation.

.. _zope.interface: https://github.com/zopefoundation/zope.interface

Changes
=======

4.6 (2019-11-12)
----------------

- Add support for Python 3.8.

- Drop support for Python 3.4.

- Fix tests on Python 2 following changes in ZODB 5.5.0.


4.5 (2018-10-10)
----------------

- Add support for Python 3.7.

- Always install ``zope.hookable`` as a dependency (the ``hook``
  extra is now empty). ``zope.hookable`` respects the PURE_PYTHON
  environment variable, and has an optional C extension.

- Make accessing names that have been moved to ``zope.interface``
  produce a ``DeprecationWarning``.


4.4.1 (2017-09-26)
------------------

- Remove obsolete call of ``searchInterface`` from
  ``interfaceToName``. See https://github.com/zopefoundation/zope.component/issues/32


4.4.0 (2017-07-25)
------------------

- Add support for Python 3.6.

- Drop support for Python 3.3.

- Drop support for "setup.py test".

- Code coverage reports are now `produced and hosted by coveralls.io
  <https://coveralls.io/github/zopefoundation/zope.component>`_, and
  PRs must keep them at 100%.

- Internal test code in ``zope.component.testfiles`` has been adjusted
  and in some cases removed.


4.3.0 (2016-08-26)
------------------

- When testing ``PURE_PYTHON`` environments under ``tox``, avoid poisoning
  the user's global wheel cache.

- Drop support for Python 2.6 and 3.2.

- Add support for Python 3.5.


4.2.2 (2015-06-04)
------------------

- Fix test cases for PyPy and PyPy3.


4.2.1 (2014-03-19)
------------------

- Add support for Python 3.4.


4.2.0 (2014-02-05)
------------------

- Update ``boostrap.py`` to version 2.2.

- Reset the cached ``adapter_hooks`` at ``zope.testing.cleanup.cleanUp``
  time (LP1100501).

- Implement ability to specify adapter and utility names in Python. Use
  the ``@zope.component.named(name)`` decorator to specify the name.


4.1.0 (2013-02-28)
------------------

- Change "ZODB3" depdendency to "persistent".

- ``tox`` now runs all tests for Python 3.2 and 3.3.

- Enable buildout for Python 3.

- Fix new failing tests.


4.0.2 (2012-12-31)
------------------

- Flesh out PyPI Trove classifiers.


4.0.1 (2012-11-21)
------------------

- Add support for Python 3.3.


4.0.0 (2012-07-02)
------------------

- Add PyPy and Python 3.2 support:

  - Security support omitted until ``zope.security`` ported.

  - Persistent registry support omitted until ``ZODB`` ported (or
    ``persistent`` factored out).

- Bring unit test coverage to 100%.

- Remove the long-deprecated ``layer`` argument to the
  ``zope.component.zcml.view`` and ``zope.component.zcml.resource``
  ZCML directives.

- Add support for continuous integration using ``tox`` and ``jenkins``.

- Got tests to run using ``setup.py test``.

- Add ``Sphinx`` documentation.

- Add ``setup.py docs`` alias (installs ``Sphinx`` and dependencies).

- Add ``setup.py dev`` alias (runs ``setup.py develop`` plus installs
  ``nose`` and ``coverage``).


3.12.1 (2012-04-02)
-------------------

- Wrap ``with site(foo)`` in try/finally (LP768151).


3.12.0 (2011-11-16)
-------------------

- Add convenience function zope.component.hooks.site (a contextmanager),
  so one can write ``with site(foo): ...``.


3.11.0 (2011-09-22)
-------------------

- Move code from ``zope.component.registry`` which implements a basic
  nonperistent component registry to ``zope.interface.registry``.  This code
  was moved from ``zope.component`` into ``zope.interface`` to make porting
  systems (such as Pyramid) that rely only on a basic component registry to
  Python 3 possible without needing to port the entirety of the
  ``zope.component`` package.  Backwards compatibility import shims have been
  left behind in ``zope.component``, so this change will not break any
  existing code.

- Move interfaces from ``zope.component.interfaces`` to
  ``zope.interface.interfaces``: ``ComponentLookupError``, ``Invalid``,
  ``IObjectEvent``, ``ObjectEvent``, ``IComponentLookup``, ``IRegistration``,
  ``IUtilityRegistration``, ``IAdapterRegistration``,
  ``ISubscriptionAdapterRegistration``, ``IHandlerRegistration``,
  ``IRegistrationEvent``, ``RegistrationEvent``, ``IRegistered``,
  ``Registered``, ``IUnregistered``, ``Unregistered``,
  ``IComponentRegistry``, and ``IComponents``.  Backwards compatibility shims
  left in place.

- Depend on ``zope.interface`` >= 3.8.0.


3.10.0 (2010-09-25)
-------------------

- Remove the ``docs`` extra and the ``sphinxdoc`` recipe.

- Create a ``security`` extra to move security-related dependencies out of the
  ``test`` extra.

- Use the new ``zope.testrunner`` package for tests.

- Add a basic test for the ``configure.zcml`` file provided.


3.9.5 (2010-07-09)
------------------

- Fix test requirements specification.


3.9.4 (2010-04-30)
------------------

- Prefer the standard library ``doctest`` to the one from ``zope.testing``.


3.9.3 (2010-03-08)
------------------

- The ZCML directives provided by ``zope.component`` now register the
  components in the registry returned by ``getSiteManager`` instead of the
  global registry. This change allows the hooking of the ``getSiteManager``
  method before the load of a ZCML file to register the components in a
  custom registry.


3.9.2 (2010-01-22)
------------------

- Fix a bug introduced by recent refactoring, where passing
  ``CheckerPublic`` to ``securityAdapterFactory`` wrongly wrapped the factory
  into a ``LocatingUntrustedAdapterFactory``.


3.9.1 (2010-01-21)
------------------

- Modify the tests to avoid allowing the tested testrunner to be influenced
  by options of the outer testrunner, such a the ``-v`` option.


3.9.0 (2010-01-21)
------------------

- Add testlayer support. It is now possible to load a ZCML file within
  tests more easily. See ``src/zope/component/testlayer.py`` and
  ``src/zope/component/testlayer.txt``.


3.8.0 (2009-11-16)
------------------

- Remove the dependencies on ``zope.proxy`` and ``zope.security`` from the
  zcml extra: ``zope.component`` no longer has a hard dependency on them;
  the support for security proxied components ZCML registrations is enabled
  only if ``zope.security`` and ``zope.proxy`` are available.

- Move the ``IPossibleSite`` and ``ISite`` interfaces here from
  ``zope.location`` as they are dealing with ``zope.component``'s concept of
  a site, but not with location.

- Move the ``zope.site.hooks`` functionality to ``zope.component.hooks`` as it
  isn't actually dealing with ``zope.site``'s concept of a site.


3.7.1 (2009-07-24)
------------------

- Fix a problem, where ``queryNextUtility`` could fail if the context could
  not be adapted to a ``IComponentLookup``.

- Fix 2 related bugs:

  When a utility is registered and there was previously a utility
  registered for the same interface and name, then the old utility is
  unregistered.  The 2 bugs related to this:

  - There was no ``Unregistered`` for the implicit unregistration. Now
    there is.

  - The old utility was still held and returned by
    ``getAllUtilitiesRegisteredFor``.  In other words, it was still
    considered registered, eeven though it wasn't.  A particularly
    negative consequence of this is that the utility is held in memory
    or in the database even though it isn't used.


3.7.0 (2009-05-21)
------------------

- Ensure that ``HookableTests`` are run by the testrunner.

- Add ``zope:view`` and ``zope:resource`` implementations into
  ``zope.component.zcml`` (dependency loaded with ``zope.component [zcml]``).


3.6.0 (2009-03-12)
------------------

- IMPORTANT: the interfaces that were defined in the
  ``zope.component.bbb.interfaces`` and deprecated for years are
  now (re)moved. However, some packages, including part of zope
  framework were still using those interfaces. They will be adapted
  for this change. If you were using some of those interfaces, you
  need to adapt your code as well:

   - Move ``IView`` and ``IDefaultViewName`` to ``zope.publisher.interfaces``.

   - Move ``IResource`` to ``zope.app.publisher.interfaces``.

   - Remove ``IContextDependent``, ``IPresentation``, ``IPresentationRequest``,
     ``IResourceFactory``, and ``IViewFactory`` completely.

     If you used ``IViewFactory`` in context of ``zope.app.form``, there's now
     ``IWidgetFactory`` in the ``zope.app.form.interfaces`` instead.

- Move ``getNextUtility`` / ``queryNextUtility`` functions here from
  ``zope.site`` (they were in ``zope.app.component`` even earlier).

- Add a pure-Python ``hookable`` implementation, for use when
  ``zope.hookable`` is not present.

- Remove use of ``zope.deferredimport`` by breaking import cycles.

- Cleanup package documentation and changelog a bit. Add sphinx-based
  documentation building command to the buildout.

- Remove deprecated code.

- Change package's mailing list address to zope-dev at zope.org, because
  zope3-dev at zope.org is now retired.


3.5.1 (2008-07-25)
------------------

- Fix bug introduced in 3.5.0: ``<utility factory="...">`` no longer supported
  interfaces declared in Python and always wanted an explicit
  ``provides="..."`` attribute. https://bugs.launchpad.net/zope3/+bug/251865


3.5.0 (2008-07-25)
------------------

- Support registration of utilities via factories through the component
  registry and return factory information in the registration information.
  Fixes https://bugs.launchpad.net/zope3/+bug/240631

- Optimize ``un/registerUtility`` by storing an optimized data structure for
  efficient retrieval of already registered utilities. This avoids looping over
  all utilities when registering a new one.


3.4.0 (2007-09-29)
------------------

No further changes since 3.4.0a1.


3.4.0a1 (2007-04-22)
--------------------

Corresponds to ``zope.component`` from Zope 3.4.0a1.

- In the Zope 3.3.x series, ``zope.component`` was simplified yet once
  more.  See http://wiki.zope.org/zope3/LocalComponentManagementSimplification
  for the proposal describing the changes.


3.2.0.2 (2006-04-15)
--------------------

- Fix packaging bug:  ``package_dir`` must be a *relative* path.


3.2.0.1 (2006-04-14)
--------------------

- Packaging change: suppress inclusion of ``setup.cfg`` in ``sdist`` builds.


3.2.0 (2006-01-05)
------------------

Corresponds to the verison of the ``zope.component`` package shipped as part
of the Zope 3.2.0 release.

- Deprecated services and related APIs. The adapter and utility registries
  are now available directly via the site manager's 'adapters' and 'utilities'
  attributes, respectively.  Services are accessible, but deprecated, and
  will be removed in Zope 3.3.

- Deprecated all presentation-related APIs, including all view-related
  API functions. Use the adapter API functions instead.
  See http://dev.zope.org/Zope3/ImplementViewsAsAdapters`

- Deprecated ``contextdependent`` package:  site managers are now looked up
  via a thread global, set during URL traversal.  The ``context`` argument
  is now always optional, and should no longer be passed.


3.0.0 (2004-11-07)
------------------

Corresponds to the verison of the ``zope.component`` package shipped as part of
the Zope X3.0.0 release.


