"""This is a module that adds configuration to the argument parser regarding
paths for certificates"""
from certbot.compat import os
from certbot._internal.cli import (
    read_file,
    flag_default,
    config_help
)


def _paths_parser(helpful):
    add = helpful.add
    verb = helpful.verb
    if verb == "help":
        verb = helpful.help_arg

    cph = "Path to where certificate is saved (with auth --csr), installed from, or revoked."
    sections = ["paths", "install", "revoke", "certonly", "manage"]
    if verb == "certonly":
        add(sections, "--cert-path", type=os.path.abspath,
            default=flag_default("auth_cert_path"), help=cph)
    elif verb == "revoke":
        add(sections, "--cert-path", type=read_file, required=False, help=cph)
    else:
        add(sections, "--cert-path", type=os.path.abspath, help=cph)

    section = "paths"
    if verb in ("install", "revoke"):
        section = verb
    # revoke --key-path reads a file, install --key-path takes a string
    add(section, "--key-path",
        type=((verb == "revoke" and read_file) or os.path.abspath),
        help="Path to private key for certificate installation "
             "or revocation (if account key is missing)")

    default_cp = None
    if verb == "certonly":
        default_cp = flag_default("auth_chain_path")
    add(["paths", "install"], "--fullchain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a full certificate chain (certificate plus chain).")
    add("paths", "--chain-path", default=default_cp, type=os.path.abspath,
        help="Accompanying path to a certificate chain.")
    add("paths", "--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("paths", "--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("paths", "--logs-dir", default=flag_default("logs_dir"),
        help="Logs directory.")
    add("paths", "--server", default=flag_default("server"),
        help=config_help("server"))
