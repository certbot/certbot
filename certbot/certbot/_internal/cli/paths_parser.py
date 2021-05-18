"""This is a module that adds configuration to the argument parser regarding
paths for certificates"""
from certbot._internal.cli.cli_utils import config_help
from certbot._internal.cli.cli_utils import flag_default
from certbot.compat import os


def _paths_parser(helpful):
    add = helpful.add
    verb = helpful.verb
    if verb == "help":
        verb = helpful.help_arg

    cpkwargs = {
        "type": os.path.abspath,
        "help": "Path to where certificate is saved (with certonly --csr), installed "
                "from, or revoked"
    }
    if verb == "certonly":
        cpkwargs["default"] = flag_default("auth_cert_path")
    add(["paths", "install", "revoke", "certonly", "manage"], "--cert-path", **cpkwargs)

    section = "paths"
    if verb in ("install", "revoke"):
        section = verb
    add(section, "--key-path", type=os.path.abspath,
        help="Path to private key for certificate installation "
             "or revocation (if account key is missing)")

    default_cp = None
    if verb == "certonly":
        default_cp = flag_default("auth_chain_path")
    add(["paths", "install"], "--fullchain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a full certificate chain (certificate plus chain).")
    add(["paths", "install"], "--chain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a certificate chain.")
    add("paths", "--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("paths", "--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("paths", "--logs-dir", default=flag_default("logs_dir"),
        help="Logs directory.")
    add("paths", "--server", default=flag_default("server"),
        help=config_help("server"))
