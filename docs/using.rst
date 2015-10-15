==============================
Using the Let's Encrypt client
==============================


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


.. _prerequisites:

Installation and Usage
======================

To install and run the client you just need to type:

.. code-block:: shell

   ./letsencrypt-auto

.. warning:: Please do **not** use ``python setup.py install``.  That mode of
             operation might corrupt your operating system and is **not supported**
             by the Let's Encrypt team!

The ``letsencrypt`` commandline tool has a builtin help:

.. code-block:: shell

   ./letsencrypt-auto --help


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

Notes on OS depedencies
=======================

OS level dependencies are managed by scripts in ``bootstrap``.  Some notes
are provided here mainly for the :ref:`developers <hacking>` reference.

In general:

* ``sudo`` is required as a suggested way of running privileged process
* `Augeas`_ is required for the Python bindings
* ``virtualenv`` and ``pip`` are used for managing other python library
  dependencies


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


FreeBSD
-------

.. code-block:: shell

   sudo ./bootstrap/freebsd.sh

Bootstrap script for FreeBSD uses ``pkg`` for package installation,
i.e. it does not use ports.

FreeBSD by default uses ``tcsh``. In order to activate virtulenv (see
below), you will need a compatbile shell, e.g. ``pkg install bash &&
bash``.




Running with Docker
===================

Docker_ is another way to quickly obtaintesting certs. From the
server that the domain your requesting a cert for resolves to,
`install Docker`_, issue the following command:

.. code-block:: shell

   sudo docker auth -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/letsencrypt:latest

and follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/docker/userguide/


