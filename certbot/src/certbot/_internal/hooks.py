"""Facilities for implementing hooks that call shell commands."""

import logging
from typing import Optional

from certbot import configuration
from certbot import errors
from certbot import util
from certbot._internal import san
from certbot.compat import filesystem
from certbot.compat import misc
from certbot.compat import os
from certbot.display import ops as display_ops
from certbot.plugins import util as plug_util

logger = logging.getLogger(__name__)


def validate_hooks(config: configuration.NamespaceConfig) -> None:
    """Check hook commands are executable."""
    validate_hook(config.pre_hook, "pre")
    validate_hook(config.post_hook, "post")
    validate_hook(config.deploy_hook, "deploy")
    validate_hook(config.renew_hook, "renew")


def _prog(shell_cmd: str) -> Optional[str]:
    """Extract the program run by a shell command.

    :param str shell_cmd: command to be executed

    :returns: basename of command or None if the command isn't found
    :rtype: str or None

    """
    if not util.exe_exists(shell_cmd):
        plug_util.path_surgery(shell_cmd)
        if not util.exe_exists(shell_cmd):
            return None

    return os.path.basename(shell_cmd)


def validate_hook(shell_cmd: str, hook_name: str) -> None:
    """Check that a command provided as a hook is plausibly executable.

    :raises .errors.HookCommandNotFound: if the command is not found
    """
    if shell_cmd:
        cmd = shell_cmd.split(None, 1)[0]
        if not _prog(cmd):
            path = os.environ["PATH"]
            if os.path.exists(cmd):
                msg = f"{cmd}-hook command {hook_name} exists, but is not executable."
            else:
                msg = (
                    f"Unable to find {hook_name}-hook command {cmd} in the PATH.\n(PATH is "
                    f"{path})\nSee also the --disable-hook-validation option."
                )

            raise errors.HookCommandNotFound(msg)


def pre_hook(config: configuration.NamespaceConfig) -> None:
    """Run pre-hooks if they exist and haven't already been run.

    When Certbot is running with the renew subcommand, this function
    runs any hooks found in the config.renewal_pre_hooks_dir (if they
    have not already been run) followed by any pre-hook in the config.
    If hooks in config.renewal_pre_hooks_dir are run and the pre-hook in
    the config is a path to one of these scripts, it is not run twice.

    :param configuration.NamespaceConfig config: Certbot settings

    """
    all_hooks: list[str] = (list_hooks(config.renewal_pre_hooks_dir) if config.directory_hooks
        else [])
    all_hooks += [config.pre_hook] if config.pre_hook else []
    for hook in all_hooks:
        _run_pre_hook_if_necessary(hook)


executed_pre_hooks: set[str] = set()


def _run_pre_hook_if_necessary(command: str) -> None:
    """Run the specified pre-hook if we haven't already.

    If we've already run this exact command before, a message is logged
    saying the pre-hook was skipped.

    :param str command: pre-hook to be run

    """
    if command in executed_pre_hooks:
        logger.info("Pre-hook command already run, skipping: %s", command)
    else:
        _run_hook("pre-hook", command)
        executed_pre_hooks.add(command)


def post_hook(
    config: configuration.NamespaceConfig,
    renewed_sans: list[san.SAN]
) -> None:

    """Run post-hooks if defined.

    This function also registers any executables found in
    config.renewal_post_hooks_dir to be run when Certbot is used with
    the renew subcommand.

    If the verb is renew, we delay executing any post-hooks until
    :func:`run_saved_post_hooks` is called. In this case, this function
    registers all hooks found in config.renewal_post_hooks_dir to be
    called followed by any post-hook in the config. If the post-hook in
    the config is a path to an executable in the post-hook directory, it
    is not scheduled to be run twice.

    :param configuration.NamespaceConfig config: Certbot settings

    """

    all_hooks: list[str] = (list_hooks(config.renewal_post_hooks_dir) if config.directory_hooks
        else [])
    all_hooks += [config.post_hook] if config.post_hook else []
    # In the "renew" case, we save these up to run at the end
    if config.verb == "renew":
        for hook in all_hooks:
            _run_eventually(hook)
    # certonly / run
    else:
        renewed_sans_str = ' '.join(map(str, renewed_sans))
        # 32k is reasonable on Windows and likely quite conservative on other platforms
        if len(renewed_sans_str) > 32_000:
            logger.warning("Limiting RENEWED_DOMAINS environment variable to 32k characters")
            renewed_sans_str = renewed_sans_str[:32_000]
        for hook in all_hooks:
            _run_hook(
                "post-hook",
                hook,
                {
                    'RENEWED_DOMAINS': renewed_sans_str,
                    # Since other commands stop certbot execution on failure,
                    # it doesn't make sense to have a FAILED_DOMAINS variable
                    'FAILED_DOMAINS': ""
                }
            )


post_hooks: list[str] = []


def _run_eventually(command: str) -> None:
    """Registers a post-hook to be run eventually.

    All commands given to this function will be run exactly once in the
    order they were given when :func:`run_saved_post_hooks` is called.

    :param str command: post-hook to register to be run

    """
    if command not in post_hooks:
        post_hooks.append(command)


def run_saved_post_hooks(renewed_sans: list[san.SAN], failed_sans: list[san.SAN]) -> None:
    """Run any post hooks that were saved up in the course of the 'renew' verb"""

    renewed_sans_str = ' '.join(map(str, renewed_sans))
    failed_sans_str = ' '.join(map(str, failed_sans))

    # 32k combined is reasonable on Windows and likely quite conservative on other platforms
    if len(renewed_sans_str) > 16_000:
        logger.warning("Limiting RENEWED_DOMAINS environment variable to 16k characters")
        renewed_sans_str = renewed_sans_str[:16_000]

    if len(failed_sans_str) > 16_000:
        logger.warning("Limiting FAILED_DOMAINS environment variable to 16k characters")
        renewed_sans_str = failed_sans_str[:16_000]

    for cmd in post_hooks:
        _run_hook(
            "post-hook",
            cmd,
            {
                'RENEWED_DOMAINS': renewed_sans_str,
                'FAILED_DOMAINS': failed_sans_str
            }
        )


def deploy_hook(config: configuration.NamespaceConfig, sans: list[san.SAN],
                lineage_path: str) -> None:
    """Run post-issuance hook if defined.

    :param configuration.NamespaceConfig config: Certbot settings
    :param sans: domains and/or IP addresses in the obtained certificate
    :type sans: `list` of `str`
    :param str lineage_path: live directory path for the new cert

    """
    if config.deploy_hook:
        _run_deploy_hook(config.deploy_hook, sans,
                         lineage_path, config.dry_run, config.run_deploy_hooks)


def renew_hook(config: configuration.NamespaceConfig, sans: list[san.SAN],
               lineage_path: str) -> None:
    """Run post-renewal hooks.

    This function runs any hooks found in
    config.renewal_deploy_hooks_dir followed by any renew-hook in the
    config. If the renew-hook in the config is a path to a script in
    config.renewal_deploy_hooks_dir, it is not run twice.

    If Certbot is doing a dry run, no hooks are run and messages are
    logged saying that they were skipped.

    :param configuration.NamespaceConfig config: Certbot settings
    :param sans: domains and/or IP addresses in the obtained certificate
    :type sans: `list` of `san.SAN`
    :param str lineage_path: live directory path for the new cert

    """
    executed_hooks = set()
    all_hooks: list[str] = (list_hooks(config.renewal_deploy_hooks_dir)if config.directory_hooks
        else [])
    all_hooks += [config.renew_hook] if config.renew_hook else []
    for hook in all_hooks:
        if hook in executed_hooks:
            logger.info("Skipping deploy-hook '%s' as it was already run.", hook)
        else:
            _run_deploy_hook(hook, sans, lineage_path, config.dry_run, config.run_deploy_hooks)
            executed_hooks.add(hook)


def _run_deploy_hook(command: str, sans: list[san.SAN], lineage_path: str, dry_run: bool,
                     run_deploy_hooks: bool) -> None:
    """Run the specified deploy-hook (if not doing a dry run).

    If dry_run is True, command is not run and a message is logged
    saying that it was skipped. If dry_run is False, the hook is run
    after setting the appropriate environment variables.

    :param str command: command to run as a deploy-hook
    :param sans: domains and/or IP addresses in the obtained certificate
    :type sans: `list` of `san.SAN`
    :param str lineage_path: live directory path for the new cert
    :param bool dry_run: True iff Certbot is doing a dry run
    :param bool run_deploy_hooks: True if deploy hooks should run despite Certbot doing a dry run

    """
    if dry_run and not run_deploy_hooks:
        logger.info("Dry run: skipping deploy hook command: %s",
                       command)
        return

    os.environ["RENEWED_DOMAINS"] = " ".join(map(str, sans))
    os.environ["RENEWED_LINEAGE"] = lineage_path
    _run_hook("deploy-hook", command)


def _run_hook(cmd_name: str, shell_cmd: str, extra_env: Optional[dict[str, str]] = None) -> str:
    """Run a hook command.

    :param str cmd_name: the user facing name of the hook being run
    :param shell_cmd: shell command to execute
    :type shell_cmd: `list` of `str` or `str`
    :param dict extra_env: extra environment variables to set
    :type extra_env: `dict` of `str` to `str`

    :returns: stderr if there was any"""
    env = util.env_no_snap_for_external_calls()
    env.update(extra_env or {})
    returncode, err, out = misc.execute_command_status(
        cmd_name, shell_cmd, env=env)
    display_ops.report_executed_command(f"Hook '{cmd_name}'", returncode, out, err)
    return err


def list_hooks(dir_path: str) -> list[str]:
    """List paths to all hooks found in dir_path in sorted order.

    :param str dir_path: directory to search

    :returns: `list` of `str`
    :rtype: sorted list of absolute paths to executables in dir_path

    """
    allpaths = (os.path.join(dir_path, f) for f in os.listdir(dir_path))
    hooks = [path for path in allpaths if filesystem.is_executable(path) and not path.endswith('~')]
    return sorted(hooks)
