============
Contributing
============

.. _hacking:

Hacking
=======

Start by :doc:`installing dependencies and setting up Let's Encrypt
<using>`.

When you're done activate the virtualenv:

.. code-block:: shell

   source ./venv/bin/activate

This step should prepend you prompt with ``(venv)`` and save you from
typing ``./venv/bin/...``. It is also required to run some of the
`testing`_ tools. Virtualenv can be disabled at any time by typing
``deactivate``. More information can be found in `virtualenv
documentation`_.

Install the development packages:

.. code-block:: shell

   pip install -r requirements.txt -e acme -e .[dev,docs,testing] -e letsencrypt-apache -e letsencrypt-nginx -e letshelp-letsencrypt

.. note:: `-e` (short for `--editable`) turns on *editable mode* in
          which any source code changes in the current working
          directory are "live" and no further `pip install ...`
          invocations are necessary while developing.

          This is roughly equivalent to `python setup.py develop`. For
          more info see `man pip`.

The code base, including your pull requests, **must** have 100% unit
test coverage, pass our `integration`_ tests **and** be compliant with
the :ref:`coding style <coding-style>`.

.. _`virtualenv documentation`: https://virtualenv.pypa.io


Testing
-------

The following tools are there to help you:

- ``tox`` starts a full set of tests. Please make sure you run it
  before submitting a new pull request.

- ``tox -e cover`` checks the test coverage only. Calling the
  ``./tox.cover.sh`` script directly (or even ``./tox.cover.sh $pkg1
  $pkg2 ...`` for any subpackages) might be a bit quicker, though.

- ``tox -e lint`` checks the style of the whole project, while
  ``pylint --rcfile=.pylintrc path`` will check a single file or
  specific directory only.

- For debugging, we recommend ``pip install ipdb`` and putting
  ``import ipdb; ipdb.set_trace()`` statement inside the source
  code. Alternatively, you can use Python's standard library `pdb`,
  but you won't get TAB completion...


Integration
~~~~~~~~~~~

First, install `Go`_ 1.5, libtool-ltdl, mariadb-server and
rabbitmq-server and then start Boulder_, an ACME CA server::

  ./tests/boulder-start.sh

The script will download, compile and run the executable; please be
patient - it will take some time... Once its ready, you will see
``Server running, listening on 127.0.0.1:4000...``. Add an
``/etc/hosts`` entry pointing ``le.wtf`` to 127.0.0.1.  You may now
run (in a separate terminal)::

  ./tests/boulder-integration.sh && echo OK || echo FAIL

If you would like to test `letsencrypt_nginx` plugin (highly
encouraged) make sure to install prerequisites as listed in
``letsencrypt-nginx/tests/boulder-integration.sh``:

.. include:: ../letsencrypt-nginx/tests/boulder-integration.sh
   :start-line: 1
   :end-line: 2
   :code: shell

and rerun the integration tests suite.

.. _Boulder: https://github.com/letsencrypt/boulder
.. _Go: https://golang.org


Vagrant
-------

If you are a Vagrant user, Let's Encrypt comes with a Vagrantfile that
automates setting up a development environment in an Ubuntu 14.04
LTS VM. To set it up, simply run ``vagrant up``. The repository is
synced to ``/vagrant``, so you can get started with:

.. code-block:: shell

  vagrant ssh
  cd /vagrant
  ./venv/bin/pip install -r requirements.txt .[dev,docs,testing]
  sudo ./venv/bin/letsencrypt

Support for other Linux distributions coming soon.

.. note::
   Unfortunately, Python distutils and, by extension, setup.py and
   tox, use hard linking quite extensively. Hard linking is not
   supported by the default sync filesystem in Vagrant. As a result,
   all actions with these commands are *significantly slower* in
   Vagrant. One potential fix is to `use NFS`_ (`related issue`_).

.. _use NFS: http://docs.vagrantup.com/v2/synced-folders/nfs.html
.. _related issue: https://github.com/ClusterHQ/flocker/issues/516


Docker
------

OSX users will probably find it easiest to set up a Docker container for
development. Let's Encrypt comes with a Dockerfile (``Dockerfile-dev``)
for doing so. To use Docker on OSX, install and setup docker-machine using the
instructions at https://docs.docker.com/installation/mac/.

To build the development Docker image::

  docker build -t letsencrypt -f Dockerfile-dev .

Now run tests inside the Docker image:

.. code-block:: shell

  docker run -it letsencrypt bash
  cd src
  tox -e py27


Code components and layout
==========================

acme
  contains all protocol specific code
letsencrypt
  all client code


Plugin-architecture
-------------------

Let's Encrypt has a plugin architecture to facilitate support for
different webservers, other TLS servers, and operating systems.
The interfaces available for plugins to implement are defined in
`interfaces.py`_.

The most common kind of plugin is a "Configurator", which is likely to
implement the `~letsencrypt.interfaces.IAuthenticator` and
`~letsencrypt.interfaces.IInstaller` interfaces (though some
Configurators may implement just one of those).

There are also `~letsencrypt.interfaces.IDisplay` plugins,
which implement bindings to alternative UI libraries.

.. _interfaces.py: https://github.com/letsencrypt/letsencrypt/blob/master/letsencrypt/interfaces.py


Authenticators
--------------

Authenticators are plugins designed to solve challenges received from
the ACME server. From the protocol, there are essentially two
different types of challenges. Challenges that must be solved by
individual plugins in order to satisfy domain validation (subclasses
of `~.DVChallenge`, i.e. `~.challenges.DVSNI`,
`~.challenges.SimpleHTTPS`, `~.challenges.DNS`) and continuity specific
challenges (subclasses of `~.ContinuityChallenge`,
i.e. `~.challenges.RecoveryToken`, `~.challenges.RecoveryContact`,
`~.challenges.ProofOfPossession`). Continuity challenges are
always handled by the `~.ContinuityAuthenticator`, while plugins are
expected to handle `~.DVChallenge` types.
Right now, we have two authenticator plugins, the `~.ApacheConfigurator`
and the `~.StandaloneAuthenticator`. The Standalone and Apache
authenticators only solve the `~.challenges.DVSNI` challenge currently.
(You can set which challenges your authenticator can handle through the
:meth:`~.IAuthenticator.get_chall_pref`.

(FYI: We also have a partial implementation for a `~.DNSAuthenticator`
in a separate branch).


Installer
---------

Installers classes exist to actually setup the certificate and be able
to enhance the configuration. (Turn on HSTS, redirect to HTTPS,
etc). You can indicate your abilities through the
:meth:`~.IInstaller.supported_enhancements` call. We currently only
have one Installer written (still developing), `~.ApacheConfigurator`.

Installers and Authenticators will oftentimes be the same
class/object. Installers and Authenticators are kept separate because
it should be possible to use the `~.StandaloneAuthenticator` (it sets
up its own Python server to perform challenges) with a program that
cannot solve challenges itself. (Imagine MTA installers).


Installer Development
---------------------

There are a few existing classes that may be beneficial while
developing a new `~letsencrypt.interfaces.IInstaller`.
Installers aimed to reconfigure UNIX servers may use Augeas for
configuration parsing and can inherit from `~.AugeasConfigurator` class
to handle much of the interface. Installers that are unable to use
Augeas may still find the `~.Reverter` class helpful in handling
configuration checkpoints and rollback.


Display
~~~~~~~

We currently offer a pythondialog and "text" mode for displays. Display
plugins implement the `~letsencrypt.interfaces.IDisplay`
interface.


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
  https://google-styleguide.googlecode.com/svn/trunk/pyguide.html
.. _Sphinx-style: http://sphinx-doc.org/
.. _PEP 8 - Style Guide for Python Code:
  https://www.python.org/dev/peps/pep-0008


Updating the documentation
==========================

In order to generate the Sphinx documentation, run the following
commands:

.. code-block:: shell

   make -C docs clean html

This should generate documentation in the ``docs/_build/html``
directory.
