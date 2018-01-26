===============
Developer Guide
===============

.. contents:: Table of Contents
   :local:


.. _getting_started:

Getting Started
===============

Running a local copy of the client
----------------------------------

Running the client in developer mode from your local tree is a little different
than running Certbot as a user. To get set up, clone our git repository by
running:

.. code-block:: shell

   git clone https://github.com/certbot/certbot

If you're on macOS, we recommend you skip the rest of this section and instead
run Certbot in Docker. You can find instructions for how to do this :ref:`here
<docker>`. If you're running on Linux, you can run the following commands to
install dependencies and set up a virtual environment where you can run
Certbot. You will need to repeat this when Certbot's dependencies change or when
a new plugin is introduced.

.. code-block:: shell

   cd certbot
   sudo ./certbot-auto --os-packages-only
   ./tools/venv.sh

You can now run the copy of Certbot from git either by executing
``venv/bin/certbot``, or by activating the virtual environment. If you're
actively modifying and testing the code, you may want to run commands like this in
each shell where you're working:

.. code-block:: shell

   source ./venv/bin/activate
   export SERVER=https://acme-staging.api.letsencrypt.org/directory
   source tests/integration/_common.sh

After that, your shell will be using the virtual environment, your copy of
Certbot will default to requesting test (staging) certificates, and you run the
client by typing `certbot` or `certbot_test`. The latter is an alias that
includes several flags useful for testing. For instance, it sets various output
directories to point to /tmp/, and uses non-privileged ports for challenges, so
root privileges are not required.

Activating a shell with `venv/bin/activate` sets environment variables so that
Python pulls in the correct versions of various packages needed by Certbot.
More information can be found in the `virtualenv docs`_.

.. _`virtualenv docs`: https://virtualenv.pypa.io

Find issues to work on
----------------------

You can find the open issues in the `github issue tracker`_.  Comparatively
easy ones are marked `Good Volunteer Task`_.  If you're starting work on
something, post a comment to let others know and seek feedback on your plan
where appropriate.

Once you've got a working branch, you can open a pull request.  All changes in
your pull request must have thorough unit test coverage, pass our
tests, and be compliant with the :ref:`coding style <coding-style>`.

.. _github issue tracker: https://github.com/certbot/certbot/issues
.. _Good Volunteer Task: https://github.com/certbot/certbot/issues?q=is%3Aopen+is%3Aissue+label%3A%22Good+Volunteer+Task%22

.. _testing:

Testing
-------

When you are working in a file ``foo.py``, there should also be a file ``foo_test.py``
either in the same directory as ``foo.py`` or in the ``tests`` subdirectory
(if there isn't, make one). While you are working on your code and tests, run
``python foo_test.py`` to run the relevant tests.

For debugging, we recommend putting
``import ipdb; ipdb.set_trace()`` statements inside the source code.

Once you are done with your code changes, and the tests in ``foo_test.py`` pass,
run all of the unittests for Certbot with ``tox -e py27`` (this uses Python
2.7).

Once all the unittests pass, check for sufficient test coverage using
``tox -e cover``, and then check for code style with ``tox -e lint`` (all files)
or ``pylint --rcfile=.pylintrc path/to/file.py`` (single file at a time).

Once all of the above is successful, you may run the full test suite,
including integration tests, using ``tox``. We recommend running the
commands above first, because running all tests with ``tox`` is very
slow, and the large amount of ``tox`` output can make it hard to find
specific failures when they happen. Also note that the full test suite
will attempt to modify your system's Apache config if your user has sudo
permissions, so it should not be run on a production Apache server.

If you have trouble getting the full ``tox`` suite to run locally, it is
generally sufficient to open a pull request and let Github and Travis run
integration tests for you.

.. _integration:

Integration testing with the Boulder CA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To run integration tests locally, you need Docker and docker-compose installed
and working. Fetch and start Boulder using:

.. code-block:: shell

  ./tests/boulder-fetch.sh

If you have problems with Docker, you may want to try `removing all containers and
volumes`_ and making sure you have at least 1GB of memory.

Set up a certbot_test alias that enables easily running against the local
Boulder:

.. code-block:: shell

   export SERVER=http://localhost:4000/directory
   source tests/integration/_common.sh

Run the integration tests using:

.. code-block:: shell

  ./tests/boulder-integration.sh

.. _removing all containers and volumes: https://www.digitalocean.com/community/tutorials/how-to-remove-docker-images-containers-and-volumes

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
challenge provided by the ACME server. ACME currently defines three types of
challenges: HTTP, TLS-SNI, and DNS, represented by classes in `acme.challenges`.
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
that listens on port 443, but it cannot install certs; a postfix plugin would
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
  . tests/integration/_common.sh
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

Submitting a pull request
=========================

Steps:

1. Write your code!
2. Make sure your environment is set up properly and that you're in your
   virtualenv. You can do this by running ``./tools/venv.sh``.
   (this is a **very important** step)
3. Run ``tox -e lint`` to check for pylint errors. Fix any errors.
4. Run ``tox --skip-missing-interpreters`` to run the entire test suite
   including coverage. The ``--skip-missing-interpreters`` argument ignores
   missing versions of Python needed for running the tests. Fix any errors.
5. If your code touches communication with an ACME server/Boulder, you
   should run the integration tests, see `integration`_.
6. Submit the PR.
7. Did your tests pass on Travis? If they didn't, fix any errors.


Updating certbot-auto and letsencrypt-auto
==========================================
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


.. _docker:

Running the client with Docker
==============================

You can use Docker Compose to quickly set up an environment for running and
testing Certbot. This is especially useful for macOS users. To install Docker
Compose, follow the instructions at https://docs.docker.com/compose/install/.

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

    letsencrypt-auto-source/letsencrypt-auto --os-packages-only

In general...

* ``sudo`` is required as a suggested way of running privileged process
* `Python`_ 2.7 is required
* `Augeas`_ is required for the Python bindings
* ``virtualenv`` and ``pip`` are used for managing other python library
  dependencies

.. _Python: https://wiki.python.org/moin/BeginnersGuide/Download
.. _Augeas: http://augeas.net/
.. _Virtualenv: https://virtualenv.pypa.io


Debian
------

For squeeze you will need to:

- Use ``virtualenv --no-site-packages -p python`` instead of ``-p python2``.


FreeBSD
-------

Packages can be installed on FreeBSD using ``pkg``, 
or any other port-management tool (``portupgrade``, ``portmanager``, etc.) 
from the pre-built package or can be built and installed from ports. 
Either way will ensure proper installation of all the dependencies required 
for the package.

FreeBSD by default uses ``tcsh``. In order to activate virtualenv (see
above), you will need a compatible shell, e.g. ``pkg install bash &&
bash``.
