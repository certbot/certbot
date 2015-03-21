.. _hacking:

Hacking
=======

In order to start hacking, you will first have to create a development
environment. Start by `installing dependencies and setting up Let's Encrypt`_.

Now you can install the development packages:

::

    ./venv/bin/python setup.py dev

The code base, including your pull requests, **must** have 100% test statement
coverage **and** be compliant with the coding-style_.

The following tools are there to help you:

- ``./venv/bin/tox`` starts a full set of tests. Please make sure you
  run it before submitting a new pull request.

- ``./venv/bin/tox -e cover`` checks the test coverage only.

- ``./venv/bin/tox -e lint`` checks the style of the whole project,
  while ``./venv/bin/pylint --rcfile=.pylintrc file`` will check a single `file` only.

.. _installing dependencies and setting up Let's Encrypt: https://letsencrypt.readthedocs.org/en/latest/using.html

CODE COMPONENTS AND LAYOUT
==========================

letsencrypt/acme - contains all protocol specific code
letsencrypt/client - all client code
letsencrypt/scripts - just the starting point of the code, main.py

Plugin-architecture
-------------------

Let's Encrypt has a plugin architecture to facilitate support for different
webservers, other TLS servers, and operating systems.

The most common kind of plugin is a "Configurator", which is likely to
implement the "Authenticator" and "Installer" interfaces (though some
Configurators may implement just one of those).

Defined here:
https://github.com/letsencrypt/lets-encrypt-preview/blob/master/letsencrypt/client/interfaces.py

There are also "Display" plugins, which implement bindings to alternative UI
libraries.

Authenticators
--------------

Authenticators are plugins designed to solve challenges received from the
ACME server. From the protocol, there are essentially two different types
of challenges. Challenges that must be solved by individual plugins in
order to satisfy domain validation (dvsni, simpleHttps, dns) and client
specific challenges (recoveryToken, recoveryContact, pop). Client specific
challenges are always handled by the "Authenticator"
client_authenticator.py. Right now we have two DV Authenticators,
apache/configurator.py and the standalone_authenticator.py. The Standalone
and Apache authenticators only solve the DVSNI challenge currently. (You
can set which challenges your authenticator can handle through the
get_chall_pref(domain) function)

(FYI: We also have a partial implementation for a dns_authenticator in a
separate branch).

Challenge types are defined here...
(
https://github.com/letsencrypt/lets-encrypt-preview/blob/master/letsencrypt/client/constants.py#L16
)

Installer
---------

Installers classes exist to actually setup the certificate and be able
to enhance the configuration. (Turn on HSTS, redirect to HTTPS, etc). You
can indicate your abilities through the supported_enhancements call. We
currently only have one Installer written (still developing),
apache/configurator.py

Installers and Authenticators will oftentimes be the same class/object.
Installers and Authenticators are kept separate because it should be
possible to use the standalone_authenticator (it sets up its own Python
server to perform challenges) with a program that cannot solve challenges
itself. (I am imagining MTA installers).

*Display* - we currently offer a pythondialog and "text" mode for
displays. I have rewritten the interface which should be merged within the
next day (the rewrite is in the revoker branch of the repo and should be
merged within the next day)

Here is what the display interface will look like
https://github.com/letsencrypt/lets-encrypt-preview/blob/revoker/letsencrypt/client/interfaces.py#L217

Augeus
------

Some plugins, especially those designed to reconfigure UNIX servers, can take
inherit from the augeus_configurator.py class in order to more efficiently
handle common operations on UNIX server configuration files.


.. _coding-style:
Coding style
============

Please:

1. **Be consistent with the rest of the code**.

2. Read `PEP 8 - Style Guide for Python Code`_.

3. Follow the `Google Python Style Guide`_, with the exception that we
   use `Sphinx-style`_ documentation:

    ::

        def foo(arg):
            """Short description.

            :param int arg: Some number.

            :returns: Argument
            :rtype: int

            """
            return arg

4. Remember to use ``./venv/bin/pylint``.

.. _Google Python Style Guide: https://google-styleguide.googlecode.com/svn/trunk/pyguide.html
.. _Sphinx-style: http://sphinx-doc.org/
.. _PEP 8 - Style Guide for Python Code: https://www.python.org/dev/peps/pep-0008


Updating the Documentation
==========================

In order to generate the Sphinx documentation, run the following commands.

::

    cd docs
    make clean html SPHINXBUILD=../venv/bin/sphinx-build


This should generate documentation in the ``docs/_build/html`` directory.
