"""Let's Encrypt client interfaces."""
import zope.interface

# pylint: disable=no-self-argument,no-method-argument,no-init,inherit-non-class


class IAuthenticator(zope.interface.Interface):
    """Generic Let's Encrypt Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """
    def get_chall_pref(domain):
        """Return list of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: list of strings with the most preferred challenges first.
            If a type is not specified, it means the Authenticator cannot
            perform the challenge.
        :rtype: list

        """
    def perform(chall_list):
        """Perform the given challenge.

        :param list chall_list: List of namedtuple types defined in
            challenge_util.py. DvsniChall...ect..

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
        """Displays a string message

        :param str message: Message to display

        """
    def generic_menu(message, choices, input_text=""):
        """Displays a generic menu.

        :param str message: message to display
        :param tup choices: choices formated as a `list` of `tup`
        :param str input_text: instructions on how to make a selection

        """
    def generic_input(message):
        """Accept input from the user."""

    def generic_yesno(message, yes_label="Yes", no_label="No"):
        """A yes/no dialog."""

    def filter_names(names):
        """Allow the user to select which names they would like to activate."""

    def success_installation(domains):
        """Display a congratulations message for new https domains."""

    def display_certs(certs):
        """Display a list of certificates."""

    def confirm_revocation(cert):
        """Confirmation of revocation screen."""

    def more_info_cert(cert):
        """Print out all information for a given certificate dict."""

    def redirect_by_default():
        """Ask the user whether they would like to redirect to HTTPS."""


class IValidator(object):
    """Configuration validator."""

    def redirect(name):
        """Verify redirect to HTTPS."""

    def ocsp_stapling(name):
        """Verify ocsp stapling for domain."""

    def https(names):
        """Verifiy HTTPS is enabled for domain."""

    def hsts(name):
        """Verify HSTS header is enabled."""
