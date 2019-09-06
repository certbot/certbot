===============
Developer Guide
===============

.. contents:: Table of Contents
   :local:


.. _getting_started:

Getting Started
===============

Certbot has the same :ref:`system requirements <system_requirements>` when set
up for development.  While the section below will help you install Certbot and
its dependencies, Certbot needs to be run on a UNIX-like OS so if you're using
Windows, you'll need to set up a (virtual) machine running an OS such as Linux
and continue with these instructions on that UNIX-like OS.

.. _local copy:

Running a local copy of the client
----------------------------------

Running the client in developer mode from your local tree is a little different
than running Certbot as a user. To get set up, clone our git repository by
running:

.. code-block:: shell

   git clone https://github.com/certbot/certbot

If you're on macOS, we recommend you skip the rest of this section and instead
run Certbot in Docker. You can find instructions for how to do this :ref:`here
<docker-dev>`. If you're running on Linux, you can run the following commands to
install dependencies and set up a virtual environment where you can run
Certbot.

.. code-block:: shell

   cd certbot
   ./certbot-auto --debug --os-packages-only
   python tools/venv.py

If you have Python3 available and want to use it, run the ``venv3.py`` script.

.. code-block:: shell

   python tools/venv3.py

.. note:: You may need to repeat this when
  Certbot's dependencies change or when a new plugin is introduced.

You can now run the copy of Certbot from git either by executing
``venv/bin/certbot``, or by activating the virtual environment. You can do the
latter by running:

.. code-block:: shell

   source venv/bin/activate
   # or
   source venv3/bin/activate

After running this command, ``certbot`` and development tools like ``ipdb``,
``ipython``, ``pytest``, and ``tox`` are available in the shell where you ran
the command. These tools are installed in the virtual environment and are kept
separate from your global Python installation. This works by setting
environment variables so the right executables are found and Python can pull in
the versions of various packages needed by Certbot.  More information can be
found in the `virtualenv docs`_.

.. _`virtualenv docs`: https://virtualenv.pypa.io

Find issues to work on
----------------------

You can find the open issues in the `github issue tracker`_.  Comparatively
easy ones are marked `good first issue`_.  If you're starting work on
something, post a comment to let others know and seek feedback on your plan
where appropriate.

Once you've got a working branch, you can open a pull request.  All changes in
your pull request must have thorough unit test coverage, pass our
tests, and be compliant with the :ref:`coding style <coding-style>`.

.. _github issue tracker: https://github.com/certbot/certbot/issues
.. _good first issue: https://github.com/certbot/certbot/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22

.. _testing:

Testing
-------

You can test your code in several ways:

- running the `automated unit`_ tests,
- running the `automated integration`_ tests
- running an *ad hoc* `manual integration`_ test

.. _automated unit:

Running automated unit tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When you are working in a file ``foo.py``, there should also be a file ``foo_test.py``
either in the same directory as ``foo.py`` or in the ``tests`` subdirectory
(if there isn't, make one). While you are working on your code and tests, run
``python foo_test.py`` to run the relevant tests.

For debugging, we recommend putting
``import ipdb; ipdb.set_trace()`` statements inside the source code.

Once you are done with your code changes, and the tests in ``foo_test.py`` pass,
run all of the unittests for Certbot with ``tox -e py27`` (this uses Python
2.7).

Once all the unittests pass, check for sufficient test coverage using ``tox -e
py27-cover``, and then check for code style with ``tox -e lint`` (all files) or
``pylint --rcfile=.pylintrc path/to/file.py`` (single file at a time).

Once all of the above is successful, you may run the full test suite using
``tox --skip-missing-interpreters``. We recommend running the commands above
first, because running all tests like this is very slow, and the large amount
of output can make it hard to find specific failures when they happen.

.. warning:: The full test suite may attempt to modify your system's Apache
  config if your user has sudo permissions, so it should not be run on a
  production Apache server.

.. _automated integration:

Running automated integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generally it is sufficient to open a pull request and let Github and Travis run
integration tests for you. However, you may want to run them locally before submitting
your pull request. You need Docker and docker-compose installed and working.

The tox environment `integration` will setup `Pebble`_, the Let's Encrypt ACME CA server
for integration testing, then launch the Certbot integration tests.

With a user allowed to access your local Docker daemon, run:

.. code-block:: shell

  tox -e integration

Tests will be run using pytest. A test report and a code coverage report will be
displayed at the end of the integration tests execution.

.. _Pebble: https://github.com/letsencrypt/pebble

.. _manual integration:

Running manual integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also manually execute Certbot against a local instance of the `Pebble`_ ACME server.
This is useful to verify that the modifications done to the code makes Certbot behave as expected.

To do so you need:

- Docker installed, and a user with access to the Docker client,
- an available `local copy`_ of Certbot.

The virtual environment set up with `python tools/venv.py` contains two commands
that can be used once the virtual environment is activated:

.. code-block:: shell

    run_acme_server

- Starts a local instance of Pebble and runs in the foreground printing its logs.
- Press CTRL+C to stop this instance.
- This instance is configured to validate challenges against certbot executed locally.

.. code-block:: shell

    certbot_test [ARGS...]

- Execute certbot with the provided arguments and other arguments useful for testing purposes,
  such as: verbose output, full tracebacks in case Certbot crashes, *etc.*
- Execution is preconfigured to interact with the Pebble CA started with ``run_acme_server``.
- Any arguments can be passed as they would be to Certbot (eg. ``certbot_test certonly -d test.example.com``).

Here is a typical workflow to verify that Certbot successfully issued a certificate
using an HTTP-01 challenge on a machine with Python 3:

.. code-block:: shell

    python tools/venv3.py
    source venv3/bin/activate
    run_acme_server &
    certbot_test certonly --standalone -d test.example.com
    # To stop Pebble, launch `fg` to get back the background job, then press CTRL+C

Code components and layout
==========================

acme
  contains all protocol specific code
certbot
  main client code
certbot-apache and certbot-nginx
  client code to configure specific web servers
certbot.egg-info
  configuration for packaging Certbot


Plugin-architecture
-------------------

Certbot has a plugin architecture to facilitate support for
different webservers, other TLS servers, and operating systems.
The interfaces available for plugins to implement are defined in
`interfaces.py`_ and `plugins/common.py`_.

The main two plugin interfaces are `~certbot.interfaces.IAuthenticator`, which
implements various ways of proving domain control to a certificate authority,
and `~certbot.interfaces.IInstaller`, which configures a server to use a
certificate once it is issued. Some plugins, like the built-in Apache and Nginx
plugins, implement both interfaces and perform both tasks. Others, like the
built-in Standalone authenticator, implement just one interface.

There are also `~certbot.interfaces.IDisplay` plugins,
which can change how prompts are displayed to a user.

.. _interfaces.py: https://github.com/certbot/certbot/blob/master/certbot/interfaces.py
.. _plugins/common.py: https://github.com/certbot/certbot/blob/master/certbot/plugins/common.py#L34


Authenticators
--------------

Authenticators are plugins that prove control of a domain name by solving a
challenge provided by the ACME server. ACME currently defines several types of
challenges: HTTP, TLS-SNI (deprecated), TLS-ALPR, and DNS, represented by classes in `acme.challenges`.
An authenticator plugin should implement support for at least one challenge type.

An Authenticator indicates which challenges it supports by implementing
`get_chall_pref(domain)` to return a sorted list of challenge types in
preference order.

An Authenticator must also implement `perform(achalls)`, which "performs" a list
of challenges by, for instance, provisioning a file on an HTTP server, or
setting a TXT record in DNS. Once all challenges have succeeded or failed,
Certbot will call the plugin's `cleanup(achalls)` method to remove any files or
DNS records that were needed only during authentication.

Installer
---------

Installers plugins exist to actually setup the certificate in a server,
possibly tweak the security configuration to make it more correct and secure
(Fix some mixed content problems, turn on HSTS, redirect to HTTPS, etc).
Installer plugins tell the main client about their abilities to do the latter
via the :meth:`~.IInstaller.supported_enhancements` call. We currently
have two Installers in the tree, the `~.ApacheConfigurator`. and the
`~.NginxConfigurator`.  External projects have made some progress toward
support for IIS, Icecast and Plesk.

Installers and Authenticators will oftentimes be the same class/object
(because for instance both tasks can be performed by a webserver like nginx)
though this is not always the case (the standalone plugin is an authenticator
that listens on port 80, but it cannot install certs; a postfix plugin would
be an installer but not an authenticator).

Installers and Authenticators are kept separate because
it should be possible to use the `~.StandaloneAuthenticator` (it sets
up its own Python server to perform challenges) with a program that
cannot solve challenges itself (Such as MTA installers).


Installer Development
---------------------

There are a few existing classes that may be beneficial while
developing a new `~certbot.interfaces.IInstaller`.
Installers aimed to reconfigure UNIX servers may use Augeas for
configuration parsing and can inherit from `~.AugeasConfigurator` class
to handle much of the interface. Installers that are unable to use
Augeas may still find the `~.Reverter` class helpful in handling
configuration checkpoints and rollback.


.. _dev-plugin:

Writing your own plugin
~~~~~~~~~~~~~~~~~~~~~~~

Certbot client supports dynamic discovery of plugins through the
`setuptools entry points`_ using the `certbot.plugins` group. This
way you can, for example, create a custom implementation of
`~certbot.interfaces.IAuthenticator` or the
`~certbot.interfaces.IInstaller` without having to merge it
with the core upstream source code. An example is provided in
``examples/plugins/`` directory.

While developing, you can install your plugin into a Certbot development
virtualenv like this:

.. code-block:: shell

  . venv/bin/activate
  pip install -e examples/plugins/
  certbot_test plugins

Your plugin should show up in the output of the last command. If not,
it was not installed properly.

Once you've finished your plugin and published it, you can have your
users install it system-wide with `pip install`. Note that this will
only work for users who have Certbot installed from OS packages or via
pip. Users who run `certbot-auto` are currently unable to use third-party
plugins. It's technically possible to install third-party plugins into
the virtualenv used by `certbot-auto`, but they will be wiped away when
`certbot-auto` upgrades.

.. warning:: Please be aware though that as this client is still in a
   developer-preview stage, the API may undergo a few changes. If you
   believe the plugin will be beneficial to the community, please
   consider submitting a pull request to the repo and we will update
   it with any necessary API changes.

.. _`setuptools entry points`:
    http://setuptools.readthedocs.io/en/latest/pkg_resources.html#entry-points

.. _coding-style:

Coding style
============

Please:

1. **Be consistent with the rest of the code**.

2. Read `PEP 8 - Style Guide for Python Code`_.

3. Follow the `Google Python Style Guide`_, with the exception that we
   use `Sphinx-style`_ documentation::

        def foo(arg):
            """Short description.

            :param int arg: Some number.

            :returns: Argument
            :rtype: int

            """
            return arg

4. Remember to use ``pylint``.

.. _Google Python Style Guide:
  https://google.github.io/styleguide/pyguide.html
.. _Sphinx-style: http://sphinx-doc.org/
.. _PEP 8 - Style Guide for Python Code:
  https://www.python.org/dev/peps/pep-0008

Use ``certbot.compat.os`` instead of ``os``
===========================================


Python's standard library ``os`` module lacks full support for several Windows
security features about file permissions (eg. DACLs). However several files
handled by Certbot (eg. private keys) need strongly restricted access
on both Linux and Windows.

To help with this, the ``certbot.compat.os`` module wraps the standard
``os`` module, and forbids usage of methods that lack support for these Windows
security features.

As a developer, when working on Certbot or its plugins, you must use ``certbot.compat.os``
in every place you would need ``os`` (eg. ``from certbot.compat import os`` instead of
``import os``). Otherwise the tests will fail when your PR is submitted.

.. _type annotations:

Mypy type annotations
=====================

Certbot uses the `mypy`_ static type checker. Python 3 natively supports official type annotations,
which can then be tested for consistency using mypy. Python 2 doesn’t, but type annotations can
be `added in comments`_. Mypy does some type checks even without type annotations; we can find
bugs in Certbot even without a fully annotated codebase.

Certbot supports both Python 2 and 3, so we’re using Python 2-style annotations.

Zulip wrote a `great guide`_ to using mypy. It’s useful, but you don’t have to read the whole thing
to start contributing to Certbot.

To run mypy on Certbot, use ``tox -e mypy`` on a machine that has Python 3 installed.

Note that instead of just importing ``typing``, due to packaging issues, in Certbot we import from
``acme.magic_typing`` and have to add some comments for pylint like this:

.. code-block:: python

  from acme.magic_typing import Dict # pylint: disable=unused-import, no-name-in-module

Also note that OpenSSL, which we rely on, has type definitions for crypto but not SSL. We use both.
Those imports should look like this:

.. code-block:: python

  from OpenSSL import crypto
  from OpenSSL import SSL # type: ignore # https://github.com/python/typeshed/issues/2052

.. _mypy: https://mypy.readthedocs.io
.. _added in comments: https://mypy.readthedocs.io/en/latest/cheat_sheet.html
.. _great guide: https://blog.zulip.org/2016/10/13/static-types-in-python-oh-mypy/

Submitting a pull request
=========================

Steps:

1. Write your code! When doing this, you should add :ref:`mypy type annotations
   <type annotations>` for any functions you add or modify. You can check that
   you've done this correctly by running ``tox -e mypy`` on a machine that has
   Python 3 installed.
2. Make sure your environment is set up properly and that you're in your
   virtualenv. You can do this by following the instructions in the
   :ref:`Getting Started <getting_started>` section.
3. Run ``tox -e lint`` to check for pylint errors. Fix any errors.
4. Run ``tox --skip-missing-interpreters`` to run the entire test suite
   including coverage. The ``--skip-missing-interpreters`` argument ignores
   missing versions of Python needed for running the tests. Fix any errors.
5. Submit the PR. Once your PR is open, please do not force push to the branch
   containing your pull request to squash or amend commits. We use `squash
   merges <https://github.com/blog/2141-squash-your-commits>`_ on PRs and
   rewriting commits makes changes harder to track between reviews.
6. Did your tests pass on Travis? If they didn't, fix any errors.

.. _ask for help:

Asking for help
===============

If you have any questions while working on a Certbot issue, don't hesitate to
ask for help! You can do this in the Certbot channel in EFF's Mattermost
instance for its open source projects as described below.

You can get involved with several of EFF's software projects such as Certbot at
the `EFF Open Source Contributor Chat Platform
<https://opensource.eff.org/signup_user_complete/?id=6iqur37ucfrctfswrs14iscobw>`_.
By signing up for the EFF Open Source Contributor Chat Platform, you consent to
share your personal information with the Electronic Frontier Foundation, which
is the operator and data controller for this platform. The channels will be
available both to EFF, and to other users of EFFOSCCP, who may use or disclose
information in these channels outside of EFFOSCCP. EFF will use your
information, according to the `Privacy Policy <https://www.eff.org/policy>`_,
to further the mission of EFF, including hosting and moderating the discussions
on this platform.

Use of EFFOSCCP is subject to the `EFF Code of Conduct
<https://www.eff.org/pages/eppcode>`_. When investigating an alleged Code of
Conduct violation, EFF may review discussion channels or direct messages.

Updating certbot-auto and letsencrypt-auto
==========================================

.. note:: We are currently only accepting changes to certbot-auto that fix
  regressions on platforms where certbot-auto is the recommended installation
  method at https://certbot.eff.org/instructions. If you are unsure if a change
  you want to make qualifies, don't hesitate to `ask for help`_!

Updating the scripts
--------------------
Developers should *not* modify the ``certbot-auto`` and ``letsencrypt-auto`` files
in the root directory of the repository.  Rather, modify the
``letsencrypt-auto.template`` and associated platform-specific shell scripts in
the ``letsencrypt-auto-source`` and
``letsencrypt-auto-source/pieces/bootstrappers`` directory, respectively.

Building letsencrypt-auto-source/letsencrypt-auto
-------------------------------------------------
Once changes to any of the aforementioned files have been made, the
``letsencrypt-auto-source/letsencrypt-auto`` script should be updated.  In lieu of
manually updating this script, run the build script, which lives at
``letsencrypt-auto-source/build.py``:

.. code-block:: shell

   python letsencrypt-auto-source/build.py

Running ``build.py`` will update the ``letsencrypt-auto-source/letsencrypt-auto``
script.  Note that the ``certbot-auto`` and ``letsencrypt-auto`` scripts in the root
directory of the repository will remain **unchanged** after this script is run.
Your changes will be propagated to these files during the next release of
Certbot.

Opening a PR
------------
When opening a PR, ensure that the following files are committed:

1. ``letsencrypt-auto-source/letsencrypt-auto.template`` and
   ``letsencrypt-auto-source/pieces/bootstrappers/*``
2. ``letsencrypt-auto-source/letsencrypt-auto`` (generated by ``build.py``)

It might also be a good idea to double check that **no** changes were
inadvertently made to the ``certbot-auto`` or ``letsencrypt-auto`` scripts in the
root of the repository.  These scripts will be updated by the core developers
during the next release.


Updating the documentation
==========================

In order to generate the Sphinx documentation, run the following
commands:

.. code-block:: shell

   make -C docs clean html man

This should generate documentation in the ``docs/_build/html``
directory.

.. note:: If you skipped the "Getting Started" instructions above,
  run ``pip install -e ".[docs]"`` to install Certbot's docs extras modules.


.. _docker-dev:

Running the client with Docker
==============================

You can use Docker Compose to quickly set up an environment for running and
testing Certbot. To install Docker Compose, follow the instructions at
https://docs.docker.com/compose/install/.

.. note:: Linux users can simply run ``pip install docker-compose`` to get
  Docker Compose after installing Docker Engine and activating your shell as
  described in the :ref:`Getting Started <getting_started>` section.

Now you can develop on your host machine, but run Certbot and test your changes
in Docker. When using ``docker-compose`` make sure you are inside your clone of
the Certbot repository. As an example, you can run the following command to
check for linting errors::

  docker-compose run --rm --service-ports development bash -c 'tox -e lint'

You can also leave a terminal open running a shell in the Docker container and
modify Certbot code in another window. The Certbot repo on your host machine is
mounted inside of the container so any changes you make immediately take
effect. To do this, run::

  docker-compose run --rm --service-ports development bash

Now running the check for linting errors described above is as easy as::

  tox -e lint

.. _prerequisites:

Notes on OS dependencies
========================

OS-level dependencies can be installed like so:

.. code-block:: shell

   ./certbot-auto --debug --os-packages-only

In general...

* ``sudo`` is required as a suggested way of running privileged process
* `Python`_ 2.7 or 3.4+ is required
* `Augeas`_ is required for the Python bindings
* ``virtualenv`` is used for managing other Python library dependencies

.. _Python: https://wiki.python.org/moin/BeginnersGuide/Download
.. _Augeas: http://augeas.net/
.. _Virtualenv: https://virtualenv.pypa.io


FreeBSD
-------

FreeBSD by default uses ``tcsh``. In order to activate virtualenv (see
above), you will need a compatible shell, e.g. ``pkg install bash &&
bash``.
