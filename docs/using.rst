==============================
Using the Let's Encrypt client
==============================

Quick start
===========

Using Docker_ you can quickly get yourself a testing cert. From the
server that the domain your requesting a cert for resolves to,
`install Docker`_, issue the following command:

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/letsencrypt:latest

and follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/docker/userguide/


Getting the code
================

Please `install Git`_ and run the following commands:

.. code-block:: shell

   git clone https://github.com/letsencrypt/letsencrypt
   cd letsencrypt

Alternatively you could `download the ZIP archive`_ and extract the
snapshot of our repository, but it's strongly recommended to use the
above method instead.

.. _`install Git`: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
.. _`download the ZIP archive`:
   https://github.com/letsencrypt/letsencrypt/archive/master.zip


Prerequisites
=============

The demo code is supported and known to work on **Ubuntu and
Debian**. Therefore, prerequisites for other platforms listed below
are provided mainly for the :ref:`developers <hacking>` reference.

In general:

* ``sudo`` is required as a suggested way of running privileged process
* `Augeas`_ is required for the Python bindings


Ubuntu
------

.. code-block:: shell

   sudo ./bootstrap/ubuntu.sh


Debian
------

.. code-block:: shell

   sudo ./bootstrap/debian.sh

For squeeze you will need to:

- Use ``virtualenv --no-site-packages -p python`` instead of ``-p python2``.


.. _`#280`: https://github.com/letsencrypt/letsencrypt/issues/280


Mac OSX
-------

.. code-block:: shell

   ./bootstrap/mac.sh


Fedora
------

.. code-block:: shell

   sudo ./bootstrap/fedora.sh


Centos 7
--------

.. code-block:: shell

   sudo ./bootstrap/centos.sh


Installation
============

For Development and Testing
---------------------------

.. "pip install acme" doesn't search for "acme" in cwd, just like "pip
   install -e acme" does

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   source ./venv/bin/activate

This step should prepend you prompt with ``(venv)`` and save you from
typing ``./venv/bin/...``. It is also required to run some of the
`testing`_ tools. Virtualenv can be disabled at any time by typing
``deactivate``. More information can be found in `virtualenv
documentation`_.

Install the development packages:

.. code-block:: shell

   pip install -r requirements.txt -e acme -e .[dev,docs,testing] -e letsencrypt-apache -e letsencrypt-nginx

.. note:: `-e` (short for `--editable`) turns on *editable mode* in
          which any source code changes in the current working
          directory are "live" and no further `pip install ...`
          invocations are necessary while developing.

          This is roughly equivalent to `python setup.py develop`. For
          more info see `man pip`.


For Running Code Only
---------------------

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   ./venv/bin/pip install -r requirements.txt acme/ . letsencrypt-apache/ letsencrypt-nginx/


.. warning:: Please do **not** use ``python setup.py install``. Please
             do **not** attempt the installation commands as
             superuser/root and/or without Virtualenv_, e.g. ``sudo
             python setup.py install``, ``sudo pip install``, ``sudo
             ./venv/bin/...``. These modes of operation might corrupt
             your operating system and are **not supported** by the
             Let's Encrypt team!


Usage
=====

To get a new certificate run:

.. code-block:: shell

   ./venv/bin/letsencrypt auth

The ``letsencrypt`` commandline tool has a builtin help:

.. code-block:: shell

   ./venv/bin/letsencrypt --help


Configuration file
------------------

It is possible to specify configuration file with
``letsencrypt --config cli.ini`` (or shorter ``-c cli.ini``). For
instance, if you are a contributor, you might find the following
handy:

.. include:: ../examples/dev-cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

.. keep it up to date with constants.py


.. _Augeas: http://augeas.net/
.. _Virtualenv: https://virtualenv.pypa.io
