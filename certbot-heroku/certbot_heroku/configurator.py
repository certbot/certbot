"""Heroku Configuration"""
import logging
import os
import shutil
import time

import zope.interface
from acme import challenges
from certbot import errors
from certbot import interfaces
from certbot.plugins import common

from certbot_heroku.git_client import GitClient
from certbot_heroku.heroku_client import HerokuCLI, HerokuApp

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator, interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class HerokuConfigurator(common.Plugin):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Heroku configurator.
    """

    description = "Heroku Client"

    @classmethod
    def add_parser_arguments(cls, add):
        add("root", default="public", help="Directory containing static assets.")
        add("remote", default="heroku", help="git remote to push to for deployment.")
        add("branch", default="master", help="git branch to push for deployment.")

    def __init__(self, *args, **kwargs):
        """Initialize a Heroku Configurator.
        """
        super(HerokuConfigurator, self).__init__(*args, **kwargs)
        self._root = self.conf("root")
        self._remote = self.conf("remote")
        self._branch = self.conf("branch")
        self._git_client = GitClient(logger=logger, dry_run=self.config.dry_run)
        self._heroku_cli = HerokuCLI(logger=logger, dry_run=self.config.dry_run)
        self._cached_heroku_app = None
        self._new_certificate = None

    # This is called in determine_authenticator and determine_installer
    def prepare(self):
        """Prepare the authenticator/installer.

        :raises .errors.NoInstallationError: If Nginx ctl cannot be found
        :raises .errors.MisconfigurationError: If Nginx is misconfigured
        """
        pass
    
    def _heroku_app(self):
        if self._cached_heroku_app is None:
            if not self._heroku_cli.is_installed():
                raise errors.PluginError("Heroku client is not installed")
            
            token = self._heroku_cli.get_token()
            app_name = self._heroku_cli.get_app_name(remote=self._remote)
            
            self._cached_heroku_app = HerokuApp(token=token, app_name=app_name, dry_run=self.config.dry_run, logger=logger)

        return self._cached_heroku_app

    # Entry point in main.py for installing cert
    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        # pylint: disable=unused-argument
        """Deploys certificate to specified virtual host.
        """
        if fullchain_path is not None:
            cert = slurp(fullchain_path)
        elif chain_path is not None:
            cert = slurp(chain_path)
        else:
            cert = slurp(cert_path)
        
        key = slurp(key_path)
        
        new_cert = dict(key=key, certificate=cert)
        if self._new_certificate is not None and self._new_certificate != new_cert:
            raise errors.PluginError("Heroku can't handle two different certificates")
        
        self._new_certificate = new_cert

    def get_all_names(self):
        """Returns all names found in the Heroku app.

        :returns: All domains associated with the app
        :rtype: set

        """
        app = self._heroku_app()
        
        return set(app.get_domains())

    def get_all_certs_keys(self):
        """Find all existing keys, certs from configuration.

        :returns: list of tuples with form [(cert, key, path)]
            cert - str path to certificate file
            key - str path to associated key file
            path - File path to configuration file.
        :rtype: set

        """
        logger.warning("get_all_cert_keys not implemented")
        raise errors.NotSupportedError("Can't get existing keys, since they're not on the file system")

    ##################################
    # enhancement methods (IInstaller)
    ##################################
    def supported_enhancements(self):  # pylint: disable=no-self-use
        return []

    def enhance(self, domain, enhancement, options=None):
        """Enhance configuration.

        :param str domain: domain to enhance
        :param str enhancement: enhancement type defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: options for the enhancement
            See :const:`~certbot.constants.ENHANCEMENTS`
            documentation for appropriate parameter.

        """
        pass

    ######################################
    # Nginx server management (IInstaller)
    ######################################
    def restart(self):
        """Restarts server. No-op for Heroku.

        :raises .errors.MisconfigurationError: If either the reload fails.

        """
        pass

    def config_test(self):  # pylint: disable=no-self-use
        """Check the configuration of Nginx for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """
        logger.warning("config_test not implemented")
        raise errors.NotSupportedError("N/A")

    def more_info(self):
        """Human-readable string to help understand the module"""
        return ("This plugin writes challenge files into a directory where "
                "they will be served from (by default, './public'), "
                "commits them to a git branch (by default, 'master'), "
                "and pushes them to a remote (by default, 'heroku'). "
                "It then waits for the challenge files to appear on the live "
                "site before telling Let's Encrypt to check them. To use it, "
                "you must be in a git working copy of the website, with the "
                "master branch checked out and on the same commit as the "
                "remote repository's version of the branch.")

    ###################################################
    # Wrapper functions for Reverter class (IInstaller)
    ###################################################
    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in
            an attempt to save the configuration, or an error creating a
            checkpoint

        """
        if temporary:
            raise errors.NotSupportedError("Heroku does not support temporary configuration changes; title=" + title)
        
        if self._new_certificate is not None:
            logger.warning("Installing new certificate...")
            self._heroku_app().update_certificate(**self._new_certificate)
        

    def recovery_routine(self):
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        logger.warning("recovery_routine not implemented")
        raise errors.NotSupportedError("N/A")

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        logger.warning("rollback_checkpoints not implemented")
        raise errors.NotSupportedError("N/A")

    def view_config_changes(self):
        """Show all of the configuration changes that have taken place.

        :raises .errors.PluginError: If there is a problem while processing
            the checkpoints directories.

        """
        logger.warning("view_config_changes not implemented")
        raise errors.NotSupportedError("N/A")

    ###########################################################################
    # Challenges Section for IAuthenticator
    ###########################################################################
    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.HTTP01]

    # Entry point in main.py for performing challenges
    def perform(self, achalls):
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        root = self._root
        remote = self._remote
        branch = self._branch
        
        self._check_root(root)
        self._check_git(remote=remote, branch=branch)
        
        owner = os.stat(root).st_uid
        directory = root + "/" + achalls[0].URI_ROOT_PATH
        
        self._clear_directory(directory=directory)
        for achall in achalls:
            self._write_challenge(achall, directory=directory)
        self._chown_challenges(root=root, directory=directory, owner=owner)
        
        logger.warning("Committing and pushing challenges to Heroku...")
        self._commit(directory=directory)
        self._deploy(remote=remote)
        logger.warning(" ")

        return map(self._wait_for_challenge_validation, achalls)

    def _check_root(self, root):
        if not os.path.exists(root):
            raise errors.PluginError("The '" + root + "' folder doesn't exist")
    
    def _check_git(self, remote, branch):
        try:
            # Make sure we're on the right branch
            current = self._git_client.checked_out_branch()
            if current != branch:
                raise errors.PluginError("Working copy has '" + current +"' checked out, not '" + branch + "'")

            # git remote update will fail if there's no such remote, but it's also necessary
            # for is_up_to_date to actually give the right answer.
            self._git_client.update_remote(remote)

            # Now make sure the branch is up to date
            if not self._git_client.is_up_to_date(remote=remote, branch=branch):
                raise errors.PluginError("The working copy is out of date with the '" + remote + "' remote")
        
        except GitClient.Error as error:
            raise errors.PluginError(str(error))
    
    def _clear_directory(self, directory):
        if os.path.exists(directory):
            shutil.rmtree(directory)

    def _write_challenge(self, achall, directory):
        response, validation = achall.response_and_validation()
        
        if not os.path.exists(directory):
            os.makedirs(directory)

        file = directory + "/" + achall.chall.encode("token")
        with open(file, "w") as validation_file:
            validation_file.write(validation.encode())

    def _chown_challenges(self, root, directory, owner):
        while root != os.path.dirname(directory):
            directory = os.path.dirname(directory)

        os.chown(directory, owner, -1)
        for (dirpath, dirs, files) in os.walk(directory):
            for file in dirs + files:
                os.chown(os.path.join(dirpath, file), owner, -1)

    def _commit(self, directory):
        self._git_client.stage_file(directory)
    
        commit_message = "Challenges for Let's Encrypt certificate"
        if self.config.staging:
            commit_message += " (testing only)"
        self._git_client.commit(message=commit_message)
    
    def _deploy(self, remote):
        logger.debug("Pushing to '" + remote + "'...")
        self._git_client.push_to_remote(remote)
        
    def _wait_for_challenge_validation(self, achall):
        response, validation = achall.response_and_validation()
        
        logger.warning("Verifying challenge for " + achall.domain + ". This might take a few minutes if your app is restarting. (Ctrl-C to skip.)")
        try:
            while not response.simple_verify(
                    achall.chall, achall.domain,
                    achall.account_key.public_key(), self.config.http01_port):
                time.sleep(10)
        except KeyboardInterrupt:
            pass

        return response

    # called after challenges are performed
    def cleanup(self, achalls):
        """Revert all challenges."""
        pass

def slurp(path):
    with open(path, 'r') as filehandle:
        return filehandle.read()
