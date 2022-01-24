"""This module contain help information for verbs supported by certbot"""
from certbot._internal.cli.cli_constants import SHORT_USAGE
from certbot._internal.cli.cli_utils import flag_default
from certbot.compat import os

# The attributes here are:
# short: a string that will be displayed by "certbot -h commands"
# opts:  a string that heads the section of flags with which this command is documented,
#        both for "certbot -h SUBCOMMAND" and "certbot -h all"
# usage: an optional string that overrides the header of "certbot -h SUBCOMMAND"
VERB_HELP = [
    ("run (default)", {
        "short": "Obtain/renew a certificate, and install it",
        "opts": "Options for obtaining & installing certificates",
        "usage": SHORT_USAGE.replace("[SUBCOMMAND]", ""),
        "realname": "run"
    }),
    ("certonly", {
        "short": "Obtain or renew a certificate, but do not install it",
        "opts": "Options for modifying how a certificate is obtained",
        "usage": ("\n\n  certbot certonly [options] [-d DOMAIN] [-d DOMAIN] ...\n\n"
                  "This command obtains a TLS/SSL certificate without installing it anywhere.")
    }),
    ("renew", {
        "short": "Renew all certificates (or one specified with --cert-name)",
        "opts": ("The 'renew' subcommand will attempt to renew any certificates"
                 " previously obtained if they are close to expiry, and print a"
                 " summary of the results. By default, 'renew' will reuse the"
                 " plugins and options used to obtain or most recently renew each"
                 " certificate. You can test whether future renewals will succeed"
                 " with `--dry-run`."
                 " Individual certificates can be renewed with the `--cert-name`"
                 " option. Hooks are available to run commands"
                 " before and after renewal; see"
                 " https://certbot.eff.org/docs/using.html#renewal for more"
                 " information on these."),
        "usage": "\n\n  certbot renew [--cert-name CERTNAME] [options]\n\n"
    }),
    ("certificates", {
        "short": "List certificates managed by Certbot",
        "opts": "List certificates managed by Certbot",
        "usage": ("\n\n  certbot certificates [options] ...\n\n"
                  "Print information about the status of certificates managed by Certbot.")
    }),
    ("delete", {
        "short": "Clean up all files related to a certificate",
        "opts": "Options for deleting a certificate",
        "usage": "\n\n  certbot delete --cert-name CERTNAME\n\n"
    }),
    ("revoke", {
        "short": "Revoke a certificate specified with --cert-path or --cert-name",
        "opts": "Options for revocation of certificates",
        "usage": "\n\n  certbot revoke [--cert-path /path/to/fullchain.pem | "
        "--cert-name example.com] [options]\n\n"
    }),
    ("register", {
        "short": "Register for account with Let's Encrypt / other ACME server",
        "opts": "Options for account registration",
        "usage": "\n\n  certbot register --email user@example.com [options]\n\n"
    }),
    ("update_account", {
        "short": "Update existing account with Let's Encrypt / other ACME server",
        "opts": "Options for account modification",
        "usage": "\n\n  certbot update_account --email updated_email@example.com [options]\n\n"
    }),
    ("unregister", {
        "short": "Irrevocably deactivate your account",
        "opts": "Options for account deactivation.",
        "usage": "\n\n  certbot unregister [options]\n\n"
    }),
    ("install", {
        "short": "Install an arbitrary certificate in a server",
        "opts": "Options for modifying how a certificate is deployed",
        "usage": "\n\n  certbot install --cert-path /path/to/fullchain.pem "
        " --key-path /path/to/private-key [options]\n\n"
    }),
    ("rollback", {
        "short": "Roll back server conf changes made during certificate installation",
        "opts": "Options for rolling back server configuration changes",
        "usage": "\n\n  certbot rollback --checkpoints 3 [options]\n\n"
    }),
    ("plugins", {
        "short": "List plugins that are installed and available on your system",
        "opts": 'Options for the "plugins" subcommand',
        "usage": "\n\n  certbot plugins [options]\n\n"
    }),
    ("update_symlinks", {
        "short": "Recreate symlinks in your /etc/letsencrypt/live/ directory",
        "opts": ("Recreates certificate and key symlinks in {0}, if you changed them by hand "
                 "or edited a renewal configuration file".format(
                  os.path.join(flag_default("config_dir"), "live"))),
        "usage": "\n\n  certbot update_symlinks [options]\n\n"
    }),
    ("enhance", {
        "short": "Add security enhancements to your existing configuration",
        "opts": ("Helps to harden the TLS configuration by adding security enhancements "
                 "to already existing configuration."),
        "usage": "\n\n  certbot enhance [options]\n\n"
    }),
    ("show_account", {
        "short": "Show account details from an ACME server",
        "opts": 'Options useful for the "show_account" subcommand:',
        "usage": "\n\n  certbot show_account [options]\n\n"
    }),
]


# VERB_HELP is a list in order to preserve order, but a dict is sometimes useful
VERB_HELP_MAP = dict(VERB_HELP)
