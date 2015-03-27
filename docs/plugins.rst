=======
Plugins
=======

Let's Encrypt client supports dynamic discovery of plugins through the
`setuptools entry points`_. This way you can, for example, create a
custom implementation of
`~letsencrypt.client.interfaces.IAuthenticator` without having to
merge it with the core upstream source code. Example is provided in
``examples/plugins/`` directory.

.. _`setuptools entry points`:
  https://pythonhosted.org/setuptools/setuptools.html#dynamic-discovery-of-services-and-plugins
