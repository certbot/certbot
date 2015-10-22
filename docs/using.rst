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


Installation and Usage
======================

To install and run the client you just need to type:

.. code-block:: shell

   ./letsencrypt-auto

(Once letsencrypt is packaged by distributions, the command will just be
``letsencrypt``.  ``letsencrypt-auto`` is a wrapper which installs virtualized
dependencies and provides automated updates during the beta program)

.. warning:: Please do **not** use ``python setup.py install`` or ``sudo pip install`.
             Those mode of operation might corrupt your operating system and is
             **not supported** by the Let's Encrypt team!

The ``letsencrypt`` commandline tool has a builtin help:

.. code-block:: shell

   ./letsencrypt-auto --help


Configuration file
------------------

It is possible to specify configuration file with
``letsencrypt-auto --config cli.ini`` (or shorter ``-c cli.ini``). For
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


Running with Docker
===================

Docker_ is another way to quickly obtain testing certs. From the
server that the domain your requesting a cert for resolves to,
`install Docker`_, issue the following command:

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/letsencrypt:latest auth

and follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/userguide/
