"""Renewer tool to handle autorenewal and autodeployment of renewed
certs within lineages of successor certificates, according to
configuration."""

# TODO: sanity checking consistency, validity, freshness?

# TODO: call new installer API to restart servers after deployment

import os

import configobj

from letsencrypt import configuration
from letsencrypt import constants
from letsencrypt import client
from letsencrypt import crypto_util
from letsencrypt import notify
from letsencrypt import storage
from letsencrypt.plugins import disco as plugins_disco


class AttrDict(dict):
    """A trick to allow accessing dictionary keys as object
    attributes."""
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def renew(cert, old_version):
    """Perform automated renewal of the referenced cert, if possible.

    :param class:`letsencrypt.storage.RenewableCert` cert: the certificate
        lineage to attempt to renew.
    :param int old_version: the version of the certificate lineage relative
        to which the renewal should be attempted.

    :returns: int referring to newly created version of this cert lineage,
        or False if renewal was not successful."""

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
    config = configuration.NamespaceConfig(AttrDict(renewalparams))
    # XXX: this loses type data (for example, the fact that key_size
    #      was an int, not a str)
    config.rsa_key_size = int(config.rsa_key_size)
    try:
        authenticator = plugins[renewalparams["authenticator"]]
    except KeyError:
        # TODO: Notify user? (authenticator could not be found)
        return False
    authenticator = authenticator.init(config)

    authenticator.prepare()
    account = client.determine_account(config)
    # TODO: are there other ways to get the right account object, e.g.
    #       based on the email parameter that might be present in
    #       renewalparams?

    our_client = client.Client(config, account, authenticator, None)
    with open(cert.version("cert", old_version)) as f:
        sans = crypto_util.get_sans_from_cert(f.read())
    new_cert, new_key, new_chain = our_client.obtain_certificate(sans)
    if new_cert and new_key and new_chain:
        # XXX: Assumes that there was no key change.  We need logic
        #      for figuring out whether there was or not.  Probably
        #      best is to have obtain_certificate return None for
        #      new_key if the old key is to be used (since save_successor
        #      already understands this distinction!)
        return cert.save_successor(old_version, new_cert, new_key, new_chain)
        # TODO: Notify results
    else:
        # TODO: Notify negative results
        return False
    # TODO: Consider the case where the renewal was partially successful
    #       (where fewer than all names were renewed)


def main(config=constants.RENEWER_DEFAULTS):
    """main function for autorenewer script."""
    # TODO: Distinguish automated invocation from manual invocation,
    #       perhaps by looking at sys.argv[0] and inhibiting automated
    #       invocations if /etc/letsencrypt/renewal.conf defaults have
    #       turned it off. (The boolean parameter should probably be
    #       called renewer_enabled.)

    # This attempts to read the renewer config file and augment or replace
    # the renewer defaults with any options contained in that file.  If
    # renewer_config_file is undefined or if the file is nonexistent or
    # empty, this .merge() will have no effect.
    config.merge(configobj.ConfigObj(config.get("renewer_config_file", "")))

    for i in os.listdir(config["renewal_configs_dir"]):
        print "Processing", i
        if not i.endswith(".conf"):
            continue
        rc_config = configobj.ConfigObj(
            os.path.join(config["renewal_configs_dir"], i))
        try:
            cert = storage.RenewableCert(rc_config)
        except ValueError:
            # This indicates an invalid renewal configuration file, such
            # as one missing a required parameter (in the future, perhaps
            # also one that is internally inconsistent or is missing a
            # required parameter).  As a TODO, maybe we should warn the
            # user about the existence of an invalid or corrupt renewal
            # config rather than simply ignoring it.
            continue
        if cert.should_autodeploy():
            cert.update_all_links_to(cert.latest_common_version())
            # TODO: restart web server (invoke IInstaller.restart() method)
            notify.notify("Autodeployed a cert!!!", "root", "It worked!")
            # TODO: explain what happened
        if cert.should_autorenew():
            # Note: not cert.current_version() because the basis for
            # the renewal is the latest version, even if it hasn't been
            # deployed yet!
            old_version = cert.latest_common_version()
            renew(cert, old_version)
            notify.notify("Autorenewed a cert!!!", "root", "It worked!")
            # TODO: explain what happened
