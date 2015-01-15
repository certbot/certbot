"""Let's Encrypt client interfaces."""
import zope.interface

# pylint: disable=no-self-argument,no-method-argument


class IAuthenticator(zope.interface.Interface):
    """Generic Let's Encrypt Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """
    def get_chall_pref(domain):
        """Return list of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: list of strings with the most preferred challenges first.
        :rtype: list

        """
    def perform(chall_list):
        """Perform the given challenge.

        :param list chall_list: List of challenge types defined in client.py

        :returns: List of responses
            If the challenge cant be completed...
            None - Authenticator can perform challenge, but can't at this time
            False - Authenticator will never be able to perform (error)
        :rtype: `list` of dicts

        """
    def cleanup(chall_list):
        """Revert changes and shutdown after challenges complete."""


class IChallenge(zope.interface.Interface):
    """Let's Encrypt challenge."""

    def perform():
        """Perform the challenge."""

    def generate_response():
        """Generate response."""

    def cleanup():
        """Cleanup."""


class IInstaller(zope.interface.Interface):
    """Generic Let's Encrypt Installer Interface.

    Represents any server that an X509 certificate can be placed.

    """
    def get_all_names():
        """Returns all names that may be authenticated."""

    def deploy_cert(domain, cert, key, cert_chain=None):
        """Deploy certificate.

        :param str domain: domain to deploy certificate
        :param str cert: certificate filename
        :param str key: private key filename

        """

    # def choose_virtual_host(domain):
    #    """Chooses a virtual host based on a given domain name."""

    # def enable_redirect(ssl_vhost):
    #    """Redirect all traffic to the given ssl_vhost (port 80 => 443)."""

    # def enable_hsts(ssl_vhost):
    #    """Enable HSTS on the given ssl_vhost."""

    # def enable_ocsp_stapling(ssl_vhost):
    #    """Enable OCSP stapling on given ssl_vhost."""

    def enhance(domain, enhancment, options=None):
        """Peform a configuration enhancment.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in CONFIG.ENHANCEMENTS
        :param options: flexible options parameter for enhancement
        :type options: Check documentation of
            :class:`letsencrypt.client.CONFIG.ENHANCEMENTS` for expected options
            for each enhancement.

        """

    def supported_enhancements():
        """Returns a list of supported enhancments.

        :returns: supported enhancments which should be a subset of the
        enhancments in :class:`letsencrypt.client.CONFIG.ENHANCEMENTS`
        :rtype: `list` of `str`

        """

    def get_all_certs_keys():
        """Retrieve all certs and keys set in configuration.

        :returns: list of tuples with form [(cert, key, path)]
            cert - str path to certificate file
            key - str path to associated key file
            path - file path to configuration file
        :rtype: list

        """

    # def enable_site(vhost):
    #     """Enable the site at the given vhost.

    #     :param vhost: domain 

    #     """

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

    def view_config_changes():
        """Display all of the LE config changes."""

    def config_test():
        """Make sure the configuration is valid."""

    def restart():
        """Restart or refresh the server content."""


class IDisplay(zope.interface.Interface):
    """Generic display."""

    def generic_notification(message):
        pass

    def generic_menu(message, choices, input_text=""):
        pass

    def generic_input(message):
        pass

    def generic_yesno(message, yes_label="Yes", no_label="No"):
        pass

    def filter_names(names):
        pass

    def success_installation(domains):
        pass

    def display_certs(certs):
        pass

    def confirm_revocation(cert):
        pass

    def more_info_cert(cert):
        pass

    def redirect_by_default():
        pass


class IValidator(object):
    """Configuration validator."""

    def redirect(name):
        pass

    def ocsp_stapling(name):
        pass

    def https(names):
        pass

    def hsts(name):
        pass
