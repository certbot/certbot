.. _hacking:

Hacking
=======

In order to start hacking, you will first have to create a development
environment:

::

    ./venv/bin/python setup.py dev

The code base, including your pull requests, **must** have 100% test statement
coverage **and** be compliant with the :ref:`coding-style`.

The following tools are there to help you:

- ``./venv/bin/tox`` starts a full set of tests. Please make sure you
  run it before submitting a new pull request.

- ``./venv/bin/tox -e cover`` checks the test coverage only.

- ``./venv/bin/tox -e lint`` checks the style of the whole project,
  while ``./venv/bin/pylint --rcfile=.pylintrc file`` will check a single `file` only.

.. _coding-style:
	
Vagrant
=======

If you are a Vagrant user, Let's Encrypt comes with a Vagrantfile that automates
setting up a development environment in an Ubuntu 14.04 LTS VM. To set it up,
simply run ``vagrant up``. The repository is synced to ``/vagrant``, so you can
get started with:

::

	 vagrant ssh
	 cd /vagrant
	 ./venv/bin/python setup.py install
	 sudo ./venv/bin/letsencrypt

Support for other Linux distributions coming soon.

**Note:** Unfortunately, Python distutils and, by extension, setup.py and tox,
use hard linking quite extensively. Hard linking is not supported by the
default sync filesystem in Vagrant. As a result, all actions with these
commands are *significantly slower* in Vagrant. One potential fix is to `use
NFS`_ (`related issue`_).

.. _use NFS: http://docs.vagrantup.com/v2/synced-folders/nfs.html
.. _related issue: https://github.com/ClusterHQ/flocker/issues/516

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
