"""This module creates subparsers for the argument parser"""
from typing import TYPE_CHECKING

from certbot import interfaces
from certbot._internal import constants
from certbot._internal.cli.cli_utils import _EncodeReasonAction
from certbot._internal.cli.cli_utils import _user_agent_comment_type
from certbot._internal.cli.cli_utils import CaseInsensitiveList
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.cli.cli_utils import read_file

if TYPE_CHECKING:
    from certbot._internal.cli import helpful


def _create_subparsers(helpful: "helpful.HelpfulArgumentParser") -> None:
    from certbot._internal.client import sample_user_agent  # avoid import loops
    helpful.add(
        None, "--user-agent", default=flag_default("user_agent"),
        help='Set a custom user agent string for the client. User agent strings allow '
             'the CA to collect high level statistics about success rates by OS, '
             'plugin and use case, and to know when to deprecate support for past Python '
             "versions and flags. If you wish to hide this information from the Let's "
             'Encrypt server, set this to "". '
             '(default: {0}). The flags encoded in the user agent are: '
             '--duplicate, --force-renew, --allow-subset-of-names, -n, and '
             'whether any hooks are set.'.format(sample_user_agent()))
    helpful.add(
        None, "--user-agent-comment", default=flag_default("user_agent_comment"),
        type=_user_agent_comment_type,
        help="Add a comment to the default user agent string. May be used when repackaging Certbot "
             "or calling it from another tool to allow additional statistical data to be collected."
             " Ignored if --user-agent is set. (Example: Foo-Wrapper/1.0)")
    helpful.add("certonly",
                "--csr", default=flag_default("csr"), type=read_file,
                help="Path to a Certificate Signing Request (CSR) in DER or PEM format."
                " Currently --csr only works with the 'certonly' subcommand.")
    helpful.add("revoke",
                "--reason", dest="reason",
                choices=CaseInsensitiveList(constants.REVOCATION_REASONS.keys()),
                action=_EncodeReasonAction, default=flag_default("reason"),
                help="Specify reason for revoking certificate. (default: unspecified)")
    helpful.add("revoke",
                "--delete-after-revoke", action="store_true",
                default=flag_default("delete_after_revoke"),
                help="Delete certificates after revoking them, along with all previous and later "
                "versions of those certificates. (default: False)")
    helpful.add("revoke",
                "--no-delete-after-revoke", action="store_false",
                dest="delete_after_revoke",
                default=flag_default("delete_after_revoke"),
                help="Do not delete certificates after revoking them. This "
                     "option should be used with caution because the 'renew' "
                     "subcommand will attempt to renew undeleted revoked "
                     "certificates. (default: True)")
    helpful.add("rollback",
                "--checkpoints", type=int, metavar="N",
                default=flag_default("rollback_checkpoints"),
                help="Revert configuration N number of checkpoints.")
    helpful.add("plugins",
                "--init", action="store_true", default=flag_default("init"),
                help="Initialize plugins.")
    helpful.add("plugins",
                "--prepare", action="store_true", default=flag_default("prepare"),
                help="Initialize and prepare plugins.")
    helpful.add("plugins",
                "--authenticators", action="append_const", dest="ifaces",
                default=flag_default("ifaces"),
                const=interfaces.Authenticator, help="Limit to authenticator plugins only.")
    helpful.add("plugins",
                "--installers", action="append_const", dest="ifaces",
                default=flag_default("ifaces"),
                const=interfaces.Installer, help="Limit to installer plugins only.")
