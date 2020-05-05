=======================
Backwards Compatibility
=======================

All Certbot components including `acme <https://acme-python.readthedocs.io/>`_,
Certbot, and :ref:`non-third party plugins <plugins>` follow `Semantic
Versioning <https://semver.org/>`_ both for its Python :doc:`API <api>` and for the
application itself. This means that we will not change behavior in a backwards
incompatible way except in a new major version of the project.

.. note:: None of this applies to the behavior of Certbot distribution
    mechanisms such as :ref:`certbot-auto <certbot-auto>` or OS packages whose
    behavior may change at any time. Semantic versioning only applies to the
    common Certbot components that are installed by various distribution
    methods.

For Certbot as an application, the command line interface and non-interactive
behavior can be considered stable with two exceptions. The first is that no
aspects of Certbot's console or log output should be considered stable and it
may change at any time. The second is that Certbot's behavior should only be
considered stable with certain files but not all. Files with which users should
expect Certbot to maintain its current behavior with are:

* ``/etc/letsencrypt/live/<domain>/{cert,chain,fullchain,privkey}.pem`` where
  ``<domain>`` is the name given to ``--cert-name``. If ``--cert-name`` is not
  set by the user, it is the first domain given to ``--domains``.
* :ref:`CLI configuration files <config-file>`
* Hook directories in ``/etc/letsencrypt/renewal-hooks``

Certbot's behavior with other files may change at any point.

Another area where Certbot should not be considered stable is its behavior when
not run in non-interactive mode which also may change at any point.

In general, if we're making a change that we expect will break some users, we
will bump the major version and will have warned about it in a prior release
when possible. For our Python API, we will issue warnings using Python's
warning module. For application level changes, we will print and log warning
messages.
