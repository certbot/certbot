"""Interfaces."""
import zope.interface


class IAuthenticator(zope.interface.Interface):
    """Generic Let's Encrypt Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """
    def perform(chall_dict):
        """Perform the given challenge"""

    def cleanup():
        """Revert changes and shutdown after challenges complete."""


class IInstaller(zope.interface.Interface):
    """Generic Let's Encrypt Installer Interface.

    Represents any server that an X509 certificate can be placed.
    With a focus on HTTPS optimizations.

    .. todo:: All optimizations should be of the form .enable("hsts")
        This will make it general towards any optimization... we should also
        define a function to glean what optimizations are available.
        Perhaps with text that describes the optimizations...

    """
    def get_all_names():
        """Returns all names that may be authenticated."""

    def deploy_cert(vhost, cert, key, cert_chain=None):
        """Deploy certificate.

        :param vhost
        :param str cert: CSR
        :param str key: Private key

        """

    def choose_virtual_host(name):
        """Chooses a virtual host based on a given domain name."""

    def enable_redirect(ssl_vhost):
        """Redirect all traffic to the given ssl_vhost (port 80 => 443)."""

    def enable_hsts(ssl_vhost):
        """Enable HSTS on the given ssl_vhost."""

    def enable_ocsp_stapling(ssl_vhost):
        """Enable OCSP stapling on given ssl_vhost."""

    def get_all_certs_keys():
        """Retrieve all certs and keys set in configuration.

        :returns: List of tuples with form [(cert, key, path)].
        :rtype: list

        """

    def enable_site(vhost):
        """Enable the site at the given vhost."""

    def save(title=None, temporary=False):
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)
        """

    def rollback_checkpoints(rollback=1):
        """Revert `rollback` number of configuration checkpoints."""

    def display_checkpoints():
        """Display the saved configuration checkpoints."""

    def config_test():
        """Make sure the configuration is valid."""

    def restart():
        """Restart or refresh the server content."""
