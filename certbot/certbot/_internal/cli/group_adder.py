"""This module contains a function to add the groups of arguments for the help
display"""
from certbot._internal.cli import VERB_HELP


def _add_all_groups(helpful):
    helpful.add_group("automation", description="Flags for automating execution & other tweaks")
    helpful.add_group("security", description="Security parameters & server settings")
    helpful.add_group("testing",
        description="The following flags are meant for testing and integration purposes only.")
    helpful.add_group("paths", description="Flags for changing execution paths & servers")
    helpful.add_group("manage",
        description="Various subcommands and flags are available for managing your certificates:",
        verbs=["certificates", "delete", "renew", "revoke", "update_symlinks"])

    # VERBS
    for verb, docs in VERB_HELP:
        name = docs.get("realname", verb)
        helpful.add_group(name, description=docs["opts"])
