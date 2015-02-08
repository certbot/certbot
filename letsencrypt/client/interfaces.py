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
            :mod:`letsencrypt.client.challenge_util` (``DvsniChall``, etc.).

        :returns: Challenge responses or if it cannot be completed then:

            ``None``
              Authenticator can perform challenge, but can't at this time
            ``False``
              Authenticator will never be able to perform (error)

        :rtype: :class:`list` of :class:`dict`

        """

    def cleanup(chall_list):
        """Revert changes and shutdown after challenges complete."""


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

    def enhance(domain, enhancement, options=None):
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~letsencrypt.client.CONFIG.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~letsencrypt.client.CONFIG.ENHANCEMENTS`
            for expected options for each enhancement.

        """

    def supported_enhancements():
        """Returns a list of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~letsencrypt.client.CONFIG.ENHANCEMENTS`
        :rtype: :class:`list` of :class:`str`

        """

    def get_all_certs_keys():
        """Retrieve all certs and keys set in configuration.

        :returns: tuples with form `[(cert, key, path)]`, where:

            - `cert` - str path to certificate file
            - `key` - str path to associated key file
            - `path` - file path to configuration file

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

    def notification(message, height, pause):
        """Displays a string message

        :param str message: Message to display
        :param int height: Height of dialog box if applicable
        :param bool pause: Whether or not the application should pause for
            confirmation (if available)

        """

    def menu(message, choices, input_text="", ok_label="OK", help_label=""):
        """Displays a generic menu.

        :param str message: message to display

        :param choices: choices
        :type choices: :class:`list` of :func:`tuple`

        :param str input_text: instructions on how to make a selection

        """

    def input(message):
        """Accept input from the user

        :param str message: message to display to the user

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        """

    def yesno(message, yes_label="Yes", no_label="No"):
        """Query the user with a yes/no question.

        :param str message: question for the user

        :returns: True for "Yes", False for "No"
        :rtype: bool

        """

    def checkbox(message, choices):
        """Allow for multiple selections from a menu.

        :param str message: message to display to the user

        :param choices: :param choices: choices
        :type choices: :class:`list` of :func:`tuple`

        """


class IValidator(zope.interface.Interface):
    """Configuration validator."""

    def redirect(name):
        """Verify redirect to HTTPS."""

    def ocsp_stapling(name):
        """Verify ocsp stapling for domain."""

    def https(names):
        """Verify HTTPS is enabled for domain."""

    def hsts(name):
        """Verify HSTS header is enabled."""
