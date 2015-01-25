================================
The Let's Encrypt Client Project
================================

Hacking
=======

In order to start hacking, you will first have to create a development
environment:

::

    ./venv/bin/python setup.py dev

The code base, including your pull requests, **must have 100% test statement
coverage and be compliant with the [coding style](#coding-style)**.

The following tools are there to help you:

- `./venv/bin/tox` starts a full set of tests. Please make sure you
  run it before submitting a new pull request.

- `./venv/bin/tox -e cover` checks the test coverage only.

- `./venv/bin/tox -e lint` checks the style of the whole project,
  while `./venv/bin/pylint --rcfile=.pylintrc file` will check a single `file` only.


Coding style
============

Most importantly, **be consistent with the rest of the code**, please.

1. Read [PEP 8 - Style Guide for Python Code]
(https://www.python.org/dev/peps/pep-0008).

2. Follow [Google Python Style Guide]
(https://google-styleguide.googlecode.com/svn/trunk/pyguide.html),
with the exception that we use [Sphinx](http://sphinx-doc.org/)-style
documentation:

::

    def foo(arg):
        """Short description.

        :param int arg: Some number.

        :returns: Argument
        :rtype: int

        """
        return arg

3. Remember to use `./venv/bin/pylint`.


Updating the Documentation
==========================

In order to generate the Sphinx documentation, run the following commands.

::

    ./venv/bin/python setup.py docs
    cd docs
    make clean html SPHINXBUILD=../venv/bin/sphinx-build


This should generate documentation in the `docs/_build/html` directory.

API documentation
=================

.. toctree::
   :glob:

   api/**
