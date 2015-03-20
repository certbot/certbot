Prerequisites
=============

The demo code is supported and known to work on **Ubuntu only** (even
closely related `Debian is known to fail`_).

Therefore, prerequisites for other platforms listed below are provided
mainly for the `hacking`_ reference.

In general:

* `swig`_ is required for compiling `m2crypto`_
* `augeas`_ is required for the ``python-augeas`` bindings

.. _Debian is known to fail: https://github.com/letsencrypt/lets-encrypt-preview/issues/68

Ubuntu
------

::

    sudo apt-get install python python-setuptools python-virtualenv python-dev \
                 gcc swig dialog libaugeas0 libssl-dev libffi-dev \
                 ca-certificates

.. Please keep the above command in sync with .travis.yml (before_install)

Mac OSX
-------

::

    sudo brew install augeas swig


Installation
============

::

    virtualenv --no-site-packages -p python2 venv
    ./venv/bin/python setup.py install
    sudo ./venv/bin/letsencrypt


Usage
=====

The letsencrypt commandline tool has a builtin help:

::

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/

.. _hacking:

Hacking
=======

In order to start hacking, you will first have to create a development
environment. Start by installing the development packages:

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
