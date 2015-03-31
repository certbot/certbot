============
Contributing
============

.. _hacking:

Hacking
=======

In order to start hacking, you will first have to create a development
environment. Start by :doc:`installing dependencies and setting up
Let's Encrypt <using>`.

Now you can install the development packages:

.. code-block:: shell

   ./venv/bin/python setup.py dev

The code base, including your pull requests, **must** have 100% test
statement coverage **and** be compliant with the :ref:`coding style
<coding-style>`.

The following tools are there to help you:

- ``./venv/bin/tox`` starts a full set of tests. Please make sure you
  run it before submitting a new pull request.

- ``./venv/bin/tox -e cover`` checks the test coverage only.

- ``./venv/bin/tox -e lint`` checks the style of the whole project,
  while ``./venv/bin/pylint --rcfile=.pylintrc file`` will check a
  single ``file`` only.

.. _installing dependencies and setting up Let's Encrypt:
  https://letsencrypt.readthedocs.org/en/latest/using.html


Vagrant
-------

If you are a Vagrant user, Let's Encrypt comes with a Vagrantfile that
automates setting up a development environment in an Ubuntu 14.04
LTS VM. To set it up, simply run ``vagrant up``. The repository is
synced to ``/vagrant``, so you can get started with:

.. code-block:: shell

  vagrant ssh
  cd /vagrant
  ./venv/bin/python setup.py install
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


Code components and layout
==========================

letsencrypt/acme
  contains all protocol specific code
letsencrypt/client
  all client code
letsencrypt/scripts
  just the starting point of the code, main.py


Plugin-architecture
-------------------

Let's Encrypt has a plugin architecture to facilitate support for
different webservers, other TLS servers, and operating systems.

The most common kind of plugin is a "Configurator", which is likely to
implement the `~letsencrypt.client.interfaces.IAuthenticator` and
`~letsencrypt.client.interfaces.IInstaller` interfaces (though some
Configurators may implement just one of those).

There are also `~letsencrypt.client.interfaces.IDisplay` plugins,
which implement bindings to alternative UI libraries.


Authenticators
--------------

Authenticators are plugins designed to solve challenges received from
the ACME server. From the protocol, there are essentially two
different types of challenges. Challenges that must be solved by
individual plugins in order to satisfy domain validation (subclasses
of `~.DVChallenge`, i.e. `~.challenges.DVSNI`,
`~.challenges.SimpleHTTPS`, `~.challenges.DNS`) and client specific
challenges (subclasses of `~.ClientChallenge`,
i.e. `~.challenges.RecoveryToken`, `~.challenges.RecoveryContact`,
`~.challenges.ProofOfPossession`). Client specific challenges are
always handled by the `~.ClientAuthenticator`. Right now we have two
DV Authenticators, `~.ApacheConfigurator` and the
`~.StandaloneAuthenticator`. The Standalone and Apache authenticators
only solve the `~.challenges.DVSNI` challenge currently. (You can set
which challenges your authenticator can handle through the
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
developing a new `~letsencrypt.client.interfaces.IInstaller`.
Installer's aimed to reconfigure UNIX servers may use Augeas for
configuration parsing and can inherit from `~.AugeasConfigurator` class
to handle much of the interface. Installers that are unable to use
Augeas may still use the `~.Reverter` class to handle configuration
checkpoints and rollback.


Display
~~~~~~~

We currently offer a pythondialog and "text" mode for displays. Display
plugins implement the `~letsencrypt.client.interfaces.IDisplay`
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

4. Remember to use ``./venv/bin/pylint``.

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

   cd docs
   make clean html SPHINXBUILD=../venv/bin/sphinx-build

This should generate documentation in the ``docs/_build/html``
directory.
