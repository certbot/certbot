"""Let's Encrypt client interfaces."""
import zope.interface

# pylint: disable=no-self-argument,no-method-argument,no-init,inherit-non-class
# pylint: disable=too-few-public-methods


class IPluginFactory(zope.interface.Interface):

    def __call__(config):
        """Create new `IPlugin`.

        :param IConfig config: Configuration.

        """

    def add_parser_arguments(add):
        """Add plugin arguments to the CLI argument parser.

        :param callable add: Function that proxies calls to
            `argparse.ArgumentParser.add_argument` prepending options
            with unique plugin name prefix.

        """
        # TODO: move to IPlugin?


class IPlugin(zope.interface.Interface):
    """Let's Encrypt plugin."""

    description = zope.interface.Attribute("Short plugin description")

    def prepare():
        """Prepare the plugin.

         Finish up any additional initialization.

         :raises letsencrypt.client.errors.LetsEncryptMisconfigurationError:
             when full initialization cannot be completed.
         :raises letsencrypt.client.errors.LetsEncryptNoInstallationError:
             when the necessary programs/files cannot be located.

        """

    def more_info():
        """Human-readable string to help the user.

        Should describe the steps taken and any relevant info to help the user
        decide which plugin to use.

        """


class IAuthenticator(IPlugin):
    """Generic Let's Encrypt Authenticator.

    Class represents all possible tools processes that have the
    ability to perform challenges and attain a certificate.

    """

    def get_chall_pref(domain):
        """Return list of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: List of challege types (subclasses of
            :class:`letsencrypt.acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: list

        """

    def perform(achalls):
        """Perform the given challenge.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~letsencrypt.client.achallenges.AnnotatedChallenge`
            instances, such that it contains types found within
            :func:`get_chall_pref` only.

        :returns: List of ACME
            :class:`~letsencrypt.acme.challenges.ChallengeResponse` instances
            or if the :class:`~letsencrypt.acme.challenges.Challenge` cannot
            be fulfilled then:

            ``None``
              Authenticator can perform challenge, but not at this time.
            ``False``
              Authenticator will never be able to perform (error).

        :rtype: :class:`list` of
            :class:`letsencrypt.acme.challenges.ChallengeResponse`

        """

    def cleanup(achalls):
        """Revert changes and shutdown after challenges complete.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~letsencrypt.client.achallenges.AnnotatedChallenge`
            instances, a subset of those previously passed to :func:`perform`.

        """


class IConfig(zope.interface.Interface):
    """Let's Encrypt user-supplied configuration.

    .. warning:: The values stored in the configuration have not been
        filtered, stripped or sanitized.

    """
    server = zope.interface.Attribute(
        "CA hostname (and optionally :port). The server certificate must "
        "be trusted in order to avoid further modifications to the client.")
    rsa_key_size = zope.interface.Attribute("Size of the RSA key.")

    config_dir = zope.interface.Attribute("Configuration directory.")
    work_dir = zope.interface.Attribute("Working directory.")
    backup_dir = zope.interface.Attribute("Configuration backups directory.")
    temp_checkpoint_dir = zope.interface.Attribute(
        "Temporary checkpoint directory.")
    in_progress_dir = zope.interface.Attribute(
        "Directory used before a permanent checkpoint is finalized.")
    cert_key_backup = zope.interface.Attribute(
        "Directory where all certificates and keys are stored. "
        "Used for easy revocation.")
    rec_token_dir = zope.interface.Attribute(
        "Directory where all recovery tokens are saved.")
    key_dir = zope.interface.Attribute("Keys storage.")
    cert_dir = zope.interface.Attribute("Certificates storage.")

    le_vhost_ext = zope.interface.Attribute(
        "SSL vhost configuration extension.")
    cert_path = zope.interface.Attribute("Let's Encrypt certificate file.")
    chain_path = zope.interface.Attribute("Let's Encrypt chain file.")


class IInstaller(IPlugin):
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
            :const:`~letsencrypt.client.constants.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~letsencrypt.client.constants.ENHANCEMENTS`
            for expected options for each enhancement.

        """

    def supported_enhancements():
        """Returns a list of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~letsencrypt.client.constants.ENHANCEMENTS`
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

    def menu(message, choices,
             ok_label="OK", cancel_label="Cancel", help_label=""):
        """Displays a generic menu.

        :param str message: message to display

        :param choices: choices
        :type choices: :class:`list` of :func:`tuple` or :class:`str`

        :param str ok_label: label for OK button
        :param str cancel_label: label for Cancel button
        :param str help_label: label for Help button

        :returns: tuple of (`code`, `index`) where
            `code` - str display exit code
            `index` - int index of the user's selection

        """

    def input(message):
        """Accept input from the user.

        :param str message: message to display to the user

        :returns: tuple of (`code`, `input`) where
            `code` - str display exit code
            `input` - str of the user's input
        :rtype: tuple

        """

    def yesno(message, yes_label="Yes", no_label="No"):
        """Query the user with a yes/no question.

        Yes and No label must begin with different letters.

        :param str message: question for the user

        :returns: True for "Yes", False for "No"
        :rtype: bool

        """

    def checklist(message, choices):
        """Allow for multiple selections from a menu.

        :param str message: message to display to the user

        :param tags: tags
        :type tags: :class:`list` of :class:`str`

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
