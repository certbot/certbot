=======
Plugins
=======

Let's Encrypt client supports dynamic discovery of plugins through the
`setuptools entry points`_. This way you can, for example, create a
custom implementation of `~letsencrypt.interfaces.IAuthenticator` or
the `~letsencrypt.interfaces.IInstaller` without having to merge it
with the core upstream source code. An example is provided in
``examples/plugins/`` directory.

.. warning:: Please be aware though that as this client is still in a
   developer-preview stage, the API may undergo a few changes. If you
   believe the plugin will be beneficial to the community, please
   consider submitting a pull request to the repo and we will update
   it with any necessary API changes.

.. _`setuptools entry points`:
  https://pythonhosted.org/setuptools/setuptools.html#dynamic-discovery-of-services-and-plugins
