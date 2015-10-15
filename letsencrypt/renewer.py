"""Renewer tool.

Renewer tool handles autorenewal and autodeployment of renewed certs
within lineages of successor certificates, according to configuration.

.. todo:: Sanity checking consistency, validity, freshness?
.. todo:: Call new installer API to restart servers after deployment

"""
import argparse
import logging
import os
import sys

import configobj
import OpenSSL
import zope.component

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import constants
from letsencrypt import colored_logging
from letsencrypt import cli
from letsencrypt import client
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import le_util
from letsencrypt import notify
from letsencrypt import storage

from letsencrypt.display import util as display_util
from letsencrypt.plugins import disco as plugins_disco


logger = logging.getLogger(__name__)


class _AttrDict(dict):
    """Attribute dictionary.

    A trick to allow accessing dictionary keys as object attributes.

    """
    def __init__(self, *args, **kwargs):
        super(_AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def renew(cert):
    """Perform automated renewal of the referenced cert, if possible.

    :param letsencrypt.storage.RenewableCert cert: The certificate
        lineage to attempt to renew.

    """
    # TODO: handle partial success (some names can be renewed but not
    #       others)
    # TODO: handle obligatory key rotation vs. optional key rotation vs.
    #       requested key rotation
    config = _prepare_config(cert)
    if config is None:
        # TODO: notify user?
        return
    try:
        config.rsa_key_size = int(config.rsa_key_size)
        config.dvsni_port = int(config.dvsni_port)
    except (AttributeError, ValueError):
        return
    authenticator_name = getattr(config, "authenticator", None)
    if authenticator_name is None:
        # TODO: notify user?
        return
    # Instantiate the appropriate authenticator
    authenticator = _get_prepared_plugin(authenticator_name, config)
    if authenticator is None:
        # TODO: notify user?
        return
    acc = account.AccountFileStorage(config).load(
        account_id=config.account)

    le_client = client.Client(config, acc, authenticator, None)
    old_version = cert.latest_common_version()
    with open(cert.version("cert", old_version)) as f:
        sans = crypto_util.get_sans_from_cert(f.read())
    new_certr, new_chain, new_key, _ = le_client.obtain_certificate(sans)
    cert.save_successor(
        old_version, OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, new_certr.body),
        new_key.pem, crypto_util.dump_pyopenssl_chain(new_chain))
    notify.notify("Autorenewed a cert!!!", "root", "It worked!")


def deploy(cert):
    """Update the cert version, restart the server, and notify the user.


    :param letsencrypt.storage.RenewableCert cert: The certificate
        lineage to deploy

    """
    cert.update_all_links_to(cert.latest_common_version())

    config = _prepare_config(cert)
    if config is None:
        # TODO: notify user?
        return
    installer_name = getattr(config, "installer", None)
    if installer_name is None:
        # TODO: notify user?
        return
    installer = _get_prepared_plugin(installer_name, config)
    if installer is None:
        # TODO: notify user?
        return
    installer.restart()

    notify.notify("Autodeployed a cert!!!", "root", "It worked!")


def _prepare_config(cert):
    """Prepares the configuration of renewal parameters for use.

    :param .storage.RenewableCert cert: The certificate
        lineage to attempt to renew.

    :returns: configuration or ``None`` if an error occurs
    :rtype: .configuration.NamespaceConfig

    """
    renewalparams = cert.configfile.get("renewalparams")
    if renewalparams is None:
        return None
    # XXX: this loses type data (for example, the fact that key_size
    #      was an int, not a str)
    config = configuration.NamespaceConfig(_AttrDict(renewalparams))
    zope.component.provideUtility(config)

    return config


def _get_prepared_plugin(plugin_name, config):
    """Returns a prepared plugin, initialized with config

    :param str plugin_type: The name of the desired plugin
    :param .configuration.NamespaceConfig config: Renewal parameters

    :returns: Prepared plugin or ``None`` if no plugin was found
    :rtype: IPlugin

    """
    plugins = plugins_disco.PluginsRegistry.find_all()
    try:
        plugin = plugins[plugin_name]
    except KeyError:
        return None

    plugin = plugin.init(config)
    plugin.prepare()

    return plugin


def _cli_log_handler(args, level, fmt):  # pylint: disable=unused-argument
    handler = colored_logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    return handler


def _paths_parser(parser):
    add = parser.add_argument_group("paths").add_argument
    add("--config-dir", default=cli.flag_default("config_dir"),
        help=cli.config_help("config_dir"))
    add("--work-dir", default=cli.flag_default("work_dir"),
        help=cli.config_help("work_dir"))
    add("--logs-dir", default=cli.flag_default("logs_dir"),
        help="Path to a directory where logs are stored.")

    return parser


def _create_parser():
    parser = argparse.ArgumentParser()
    #parser.add_argument("--cron", action="store_true", help="Run as cronjob.")
    parser.add_argument(
        "-v", "--verbose", dest="verbose_count", action="count",
        default=cli.flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")

    return _paths_parser(parser)


def main(config=None, cli_args=sys.argv[1:]):
    """Main function for autorenewer script."""
    # TODO: Distinguish automated invocation from manual invocation,
    #       perhaps by looking at sys.argv[0] and inhibiting automated
    #       invocations if /etc/letsencrypt/renewal.conf defaults have
    #       turned it off. (The boolean parameter should probably be
    #       called renewer_enabled.)

    zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    args = _create_parser().parse_args(cli_args)

    uid = os.geteuid()
    le_util.make_or_verify_dir(args.logs_dir, 0o700, uid)
    cli.setup_logging(args, _cli_log_handler, logfile='renewer.log')

    cli_config = configuration.RenewerConfiguration(args)

    config = storage.config_with_defaults(config)
    # Now attempt to read the renewer config file and augment or replace
    # the renewer defaults with any options contained in that file.  If
    # renewer_config_file is undefined or if the file is nonexistent or
    # empty, this .merge() will have no effect.  TODO: when we have a more
    # elaborate renewer command line, we will presumably also be able to
    # specify a config file on the command line, which, if provided, should
    # take precedence over this one.
    config.merge(configobj.ConfigObj(cli_config.renewer_config_file))
    # Ensure that all of the needed folders have been created before continuing
    le_util.make_or_verify_dir(cli_config.work_dir,
                               constants.CONFIG_DIRS_MODE, uid)

    for i in os.listdir(cli_config.renewal_configs_dir):
        print "Processing", i
        if not i.endswith(".conf"):
            continue
        rc_config = configobj.ConfigObj(cli_config.renewer_config_file)
        rc_config.merge(configobj.ConfigObj(
            os.path.join(cli_config.renewal_configs_dir, i)))
        rc_config.filename = os.path.join(cli_config.renewal_configs_dir, i)
        try:
            # TODO: Before trying to initialize the RenewableCert object,
            #       we could check here whether the combination of the config
            #       and the rc_config together disables all autorenewal and
            #       autodeployment applicable to this cert.  In that case, we
            #       can simply continue and don't need to instantiate a
            #       RenewableCert object for this cert at all, which could
            #       dramatically improve performance for large deployments
            #       where autorenewal is widely turned off.
            cert = storage.RenewableCert(rc_config, cli_config=cli_config)
        except errors.CertStorageError:
            # This indicates an invalid renewal configuration file, such
            # as one missing a required parameter (in the future, perhaps
            # also one that is internally inconsistent or is missing a
            # required parameter).  As a TODO, maybe we should warn the
            # user about the existence of an invalid or corrupt renewal
            # config rather than simply ignoring it.
            continue
        if cert.should_autorenew():
            renew(cert)
        if cert.should_autodeploy():
            deploy(cert)
