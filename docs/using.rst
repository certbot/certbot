==============================
Using the Let's Encrypt client
==============================

Quick start
===========

Using docker you can quickly get yourself a testing cert. From the
server that the domain your requesting a cert for resolves to,
download docker, and issue the following command

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/lets-encrypt-preview:latest

And follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.


Prerequisites
=============

The demo code is supported and known to work on **Ubuntu and
Debian**. Therefore, prerequisites for other platforms listed below
are provided mainly for the :ref:`developers <hacking>` reference.

In general:

* ``sudo`` is required as a suggested way of running privileged process
* `SWIG`_ is required for compiling `M2Crypto`_
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


.. _`#280`: https://github.com/letsencrypt/lets-encrypt-preview/issues/280


Mac OSX
-------

.. code-block:: shell

   sudo ./bootstrap/mac.sh


Fedora
------

.. code-block:: shell

   sudo ./bootstrap/fedora.sh


Centos 7
--------

.. code-block:: shell

   sudo ./bootstrap/centos.sh

For installation run this modified command (note the trailing
backslash):

.. code-block:: shell

   SWIG_FEATURES="-includeall -D__`uname -m`__-I/usr/include/openssl" \
   ./venv/bin/pip install -r requirements.txt functools32


Installation
============

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   ./venv/bin/pip install -r requirements.txt .

.. warning:: Please do **not** use ``python setup.py install``. Please
             do **not** attempt the installation commands as
             superuser/root and/or without Virtualenv_, e.g. ``sudo
             python setup.py install``, ``sudo pip install``, ``sudo
             ./venv/bin/...``. These modes of operation might corrupt
             your operating system and are **not supported** by the
             Let's Encrypt team!

.. note:: If your operating system uses SWIG 3.0.5+, you will need to
          run ``pip install -r requirements-swig-3.0.5.txt -r
          requirements.txt`` instead. Known affected systems:

          * Fedora 22
          * some versions of Mac OS X


Usage
=====

The letsencrypt commandline tool has a builtin help:

.. code-block:: shell

   ./venv/bin/letsencrypt --help


.. _Augeas: http://augeas.net/
.. _M2Crypto: https://github.com/M2Crypto/M2Crypto
.. _SWIG: http://www.swig.org/
.. _Virtualenv: https://virtualenv.pypa.io
