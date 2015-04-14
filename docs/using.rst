==============================
Using the Let's Encrypt client
==============================

Prerequisites
=============

The demo code is supported and known to work on **Ubuntu and
Debian**. Therefore, prerequisites for other platforms listed below
are provided mainly for the :ref:`developers <hacking>` reference.

In general:

* `swig`_ is required for compiling `m2crypto`_
* `augeas`_ is required for the ``python-augeas`` bindings


Ubuntu
------

.. code-block:: shell

   ./bootstrap/ubuntu.sh


Debian
------

.. code-block:: shell

   ./bootstrap/debian.sh

For squezze you will need to:

- Run ``apt-get install -y --no-install-recommends sudo`` as root
  (``sudo`` is not installed by default) before running the bootstrap
  script.
- Use ``virtualenv --no-site-packages -p python`` instead of ``-p python2``.


.. _`#280`: https://github.com/letsencrypt/lets-encrypt-preview/issues/280


Mac OSX
-------

.. code-block:: shell

   ./bootstrap/mac.sh


Installation
============

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   ./venv/bin/python setup.py install
   sudo ./venv/bin/letsencrypt


Usage
=====

The letsencrypt commandline tool has a builtin help:

.. code-block:: shell

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/
