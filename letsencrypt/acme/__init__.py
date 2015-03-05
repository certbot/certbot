"""ACME protocol implementation.

.. warning:: This module is an implementation of the draft `ACME
  protocol version 00`_, and not the latest (as of time of writing),
  "RESTified" `ACME protocol version 01`_. It should work with the
  server from the `Node.js implementation`_,  but will not work with
  Boulder_.


.. _`ACME protocol`: https://github.com/letsencrypt/acme-spec

.. _`ACME protocol version 00`:
  https://github.com/letsencrypt/acme-spec/blob/v00/draft-barnes-acme.md

.. _`ACME protocol version 01`:
  https://github.com/letsencrypt/acme-spec/blob/v01/draft-barnes-acme.md

.. _Boulder: https://github.com/letsencrypt/boulder

.. _`Node.js implementation`: https://github.com/letsencrypt/node-acme

"""
