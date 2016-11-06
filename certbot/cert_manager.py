"""Tools for managing certificates."""
from certbot import configuration
from certbot import renewal
from certbot import storage

def update_live_symlinks(config):
    """Update the certificate file family symlinks to use archive_dir.

    Use the information in the config file to make symlinks point to
    the correct archive directory.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`

    """
    renewer_config = configuration.RenewerConfiguration(config)
    for renewal_file in renewal.renewal_conf_files(renewer_config):
        storage.RenewableCert(renewal_file,
            configuration.RenewerConfiguration(renewer_config),
            update_symlinks=True)
