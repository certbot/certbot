"""Renewer tool.

Renewer tool handles autorenewal and autodeployment of renewed certs
within lineages of successor certificates, according to configuration.

.. todo:: Sanity checking consistency, validity, freshness?
.. todo:: Call new installer API to restart servers after deployment

"""
from __future__ import print_function

import argparse
import logging
import os
import sys

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


def renew(cert, old_version):
    """Perform automated renewal of the referenced cert, if possible.

    :param letsencrypt.storage.RenewableCert cert: The certificate
        lineage to attempt to renew.
    :param int old_version: The version of the certificate lineage
        relative to which the renewal should be attempted.

    :returns: A number referring to newly created version of this cert
        lineage, or ``False`` if renewal was not successful.
    :rtype: `int` or `bool`

    """
    # TODO: handle partial success (some names can be renewed but not
    #       others)
    # TODO: handle obligatory key rotation vs. optional key rotation vs.
    #       requested key rotation
    if "renewalparams" not in cert.configfile:
        # TODO: notify user?
        return False
    renewalparams = cert.configfile["renewalparams"]
    if "authenticator" not in renewalparams:
        # TODO: notify user?
        return False
    # Instantiate the appropriate authenticator
    plugins = plugins_disco.PluginsRegistry.find_all()
    config = configuration.NamespaceConfig(_AttrDict(renewalparams))
    # XXX: this loses type data (for example, the fact that key_size
    #      was an int, not a str)
    config.rsa_key_size = int(config.rsa_key_size)
    config.tls_sni_01_port = int(config.tls_sni_01_port)
    config.namespace.http01_port = int(config.namespace.http01_port)
    zope.component.provideUtility(config)
    try:
        authenticator = plugins[renewalparams["authenticator"]]
    except KeyError:
        # TODO: Notify user? (authenticator could not be found)
        return False
    authenticator = authenticator.init(config)

    authenticator.prepare()
    acc = account.AccountFileStorage(config).load(
        account_id=renewalparams["account"])

    le_client = client.Client(config, acc, authenticator, None)
    with open(cert.version("cert", old_version)) as f:
        sans = crypto_util.get_sans_from_cert(f.read())
    new_certr, new_chain, new_key, _ = le_client.obtain_certificate(sans)
    if new_chain:
        # XXX: Assumes that there was a key change.  We need logic
        #      for figuring out whether there was or not.  Probably
        #      best is to have obtain_certificate return None for
        #      new_key if the old key is to be used (since save_successor
        #      already understands this distinction!)
        return cert.save_successor(
            old_version, OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, new_certr.body.wrapped),
            new_key.pem, crypto_util.dump_pyopenssl_chain(new_chain))
        # TODO: Notify results
    else:
        # TODO: Notify negative results
        return False
    # TODO: Consider the case where the renewal was partially successful
    #       (where fewer than all names were renewed)


def _cli_log_handler(args, level, fmt):  # pylint: disable=unused-argument
    handler = colored_logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    handler.setLevel(level)
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


def main(cli_args=sys.argv[1:]):
    """Main function for autorenewer script."""
    # TODO: Distinguish automated invocation from manual invocation,
    #       perhaps by looking at sys.argv[0] and inhibiting automated
    #       invocations if /etc/letsencrypt/renewal.conf defaults have
    #       turned it off. (The boolean parameter should probably be
    #       called renewer_enabled.)

    # TODO: When we have a more elaborate renewer command line, we will
    #       presumably also be able to specify a config file on the
    #       command line, which, if provided, should take precedence over
    #       te default config files

    zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    args = _create_parser().parse_args(cli_args)

    uid = os.geteuid()
    le_util.make_or_verify_dir(args.logs_dir, 0o700, uid)
    cli.setup_logging(args, _cli_log_handler, logfile='renewer.log')

    cli_config = configuration.RenewerConfiguration(args)

    # Ensure that all of the needed folders have been created before continuing
    le_util.make_or_verify_dir(cli_config.work_dir,
                               constants.CONFIG_DIRS_MODE, uid)

    for renewal_file in os.listdir(cli_config.renewal_configs_dir):
        if not renewal_file.endswith(".conf"):
            continue
        print("Processing " + renewal_file)
        try:
            # TODO: Before trying to initialize the RenewableCert object,
            #       we could check here whether the combination of the config
            #       and the rc_config together disables all autorenewal and
            #       autodeployment applicable to this cert.  In that case, we
            #       can simply continue and don't need to instantiate a
            #       RenewableCert object for this cert at all, which could
            #       dramatically improve performance for large deployments
            #       where autorenewal is widely turned off.
            cert = storage.RenewableCert(
                            os.path.join(cli_config.renewal_configs_dir, renewal_file),
                            cli_config)
        except errors.CertStorageError:
            # This indicates an invalid renewal configuration file, such
            # as one missing a required parameter (in the future, perhaps
            # also one that is internally inconsistent or is missing a
            # required parameter).  As a TODO, maybe we should warn the
            # user about the existence of an invalid or corrupt renewal
            # config rather than simply ignoring it.
            continue
        if cert.should_autorenew():
            # Note: not cert.current_version() because the basis for
            # the renewal is the latest version, even if it hasn't been
            # deployed yet!
            old_version = cert.latest_common_version()
            renew(cert, old_version)
            notify.notify("Autorenewed a cert!!!", "root", "It worked!")
            # TODO: explain what happened
        if cert.should_autodeploy():
            cert.update_all_links_to(cert.latest_common_version())
            # TODO: restart web server (invoke IInstaller.restart() method)
            notify.notify("Autodeployed a cert!!!", "root", "It worked!")
            # TODO: explain what happened
