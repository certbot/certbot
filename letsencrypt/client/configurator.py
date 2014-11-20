import abc

class Configurator(object):
    """
    Class represents all possible webservers and configuration editors
    This includes the generic webserver which wont have configuration
    files at all, but instead create a new process to handle the DVSNI
    and other challenges.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def deploy_cert(self, vhost, cert, key , cert_chain=None):
        return

    @abc.abstractmethod
    def choose_virtual_host(self, name):
        """
        Chooses a virtual host based on a given domain name
        """
        return

    @abc.abstractmethod
    def get_all_names(self):
        """
        Returns all names found in the Configuration
        """
        return

    @abc.abstractmethod
    def enable_redirect(self, ssl_vhost):
        """
        Makes all traffic redirect to the given ssl_vhost
        ie. port 80 => 443
        """
        return

    @abc.abstractmethod
    def enable_hsts(self, ssl_vhost):
        """
        Enable HSTS on the given ssl_vhost
        """
        return

    @abc.abstractmethod
    def enable_ocsp_stapling(self, ssl_vhost):
        """
        Enable OCSP stapling on given ssl_vhost
        """
        return

    @abc.abstractmethod
    def get_all_certs_keys(self):
        """
        Retrieve all certs and keys set in configuration
        returns: list of tuples with form [(cert, key, path)]
        """
        return

    @abc.abstractmethod
    def enable_site(self, vhost):
        """
        Enable the site at the given vhost
        """
        return

    @abc.abstractmethod
    def save(self, title=None, temporary=False):
        """
        Saves all changes to the configuration files, both
        title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready
        to be a full checkpoint

        title:     string - The title of the save. If a title is given, the
                            configuration will be saved as a new checkpoint
                            and put in a timestamped directory.
                            `title` has no effect if temporary is true.
        temporary: boolean - Indicates whether the changes made will be
                             quickly reversed in the future (challenges)
        """
        return

    @abc.abstractmethod
    def revert_challenge_config(self):
        """
        This function should reload the users original configuration files
        """
        return

    @abc.abstractmethod
    def rollback_checkpoints(self, rollback = 1):
        """
        Revert `rollback` number of configuration checkpoints
        """
        return

    @abc.abstractmethod
    def display_checkpoints(self):
        """
        Display the saved configuration checkpoints
        """
        return

    @abc.abstractmethod
    def config_test(self):
        """
        Make sure the configuration is valid
        """
        return

    @abc.abstractmethod
    def restart(self):
        """
        Restart or refresh the server content
        """
        return
